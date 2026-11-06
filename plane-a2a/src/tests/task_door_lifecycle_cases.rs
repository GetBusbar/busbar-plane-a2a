// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Replay, restore and listing lifecycle regressions over existing helpers and real SDK slots.
use super::*;

fn ticket(slot: u32) -> Ticket {
    Ticket {
        slot,
        generation: 7,
    }
}
#[test]
#[allow(unsafe_code)]
fn a_full_sizes_book_never_forgets_a_pending_tickets_short_answer() {
    let unserved = unarmed_task_services();
    // SAFETY: complete immutable table advertises the full static unarmed service prefix.
    let host = unsafe { Host::from_raw(&unserved) };
    // SAFETY: same readable static service prefix; callbacks are None and borrow no state.
    let services = unsafe { Services::from_raw(&unserved) };
    let grown = Keyed::new();
    let first = ticket(1);
    let mut via = Via::new(&host, services, first, 0, &grown);
    let mut calls = 0;
    let result: Result<(), Halt> = via.issue((1, 0), |_, _, _, _| {
        calls += 1;
        if calls == 1 {
            Poll::Ready(Err(ServiceError::Short { bytes: 2, items: 0 }))
        } else {
            Poll::Pending
        }
    });
    assert_eq!(result, Err(Halt::Pending));
    let other = Via::new(&host, services, ticket(2), 0, &grown);
    for seq in 0..GROWN_MAX as u32 {
        let _ = other.grow(handle(ticket(2), seq), 1, 0);
    }
    let mut resumed = Via::new(&host, services, first, 0, &grown);
    let result = resumed.issue((1, 0), |_, _, buf, _| {
        assert_eq!(
            buf.len(),
            2,
            "a pending handle must not be answered SHORT again"
        );
        Poll::Ready(Ok(()))
    });
    assert_eq!(result, Ok(()));
}

use busbar_contract::abi::host::service::{HostSlots, ServiceOut};
use busbar_contract::abi::host::service::{RecordsGetIn, RecordsListIn};
use busbar_contract::abi::mechanism::call::RawOutcome;
use busbar_contract::abi::sdk::test_support::zeroed;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::c_void;

#[derive(Default)]
struct ListingHost {
    rows: BTreeMap<(String, String), Vec<u8>>,
    committed: BTreeMap<(String, String), Vec<u8>>,
    read_handles: std::collections::BTreeSet<u32>,
    receipt: Vec<u8>,
    publications: usize,
    pending_entries: usize,
    fail_task: bool,
    fail_second_config: bool,
    config_reads: Vec<String>,
    failed: bool,
    writes: usize,
    delivery: bool,
    first_delivery: Option<(String, String, bool)>,
    tokens: Vec<bool>,
}
thread_local! { static LISTING: RefCell<ListingHost> = RefCell::new(ListingHost::default()); }

// Each callback receives the exact service frame and exclusive output lent by the actual SDK.
#[allow(unsafe_code)]
extern "C" fn listing_get(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: this callback is installed only in records_get; all input text/buffers live through
    // this call. We check both output capacities before writing either region.
    unsafe {
        let i = &*input.cast::<RecordsGetIn>();
        let kind = std::str::from_utf8(std::slice::from_raw_parts(i.kind.ptr, i.kind.len))
            .unwrap()
            .to_string();
        let key = std::str::from_utf8(std::slice::from_raw_parts(i.key.ptr, i.key.len))
            .unwrap()
            .to_string();
        let (failed, value) = LISTING.with(|s| {
            let mut s = s.borrow_mut();
            if kind == crate::records::KIND_PUSH_CONFIG && s.read_handles.insert(i.head.handle.seq)
            {
                s.config_reads.push(key.clone());
            }
            let failed = (s.fail_task && kind == crate::records::KIND_TASK)
                || (s.fail_second_config
                    && kind == crate::records::KIND_PUSH_CONFIG
                    && key.ends_with("/t2"));
            (failed, s.rows.get(&(kind, key)).cloned())
        });
        let outcome = if failed {
            Outcome::Failed
        } else {
            Outcome::Ready
        };
        let raw = RawOutcome::of(outcome);
        let mut answer = ServiceOut {
            size: std::mem::size_of::<ServiceOut>() as u32,
            outcome: raw,
            ..ServiceOut::ZERO
        };
        if !failed {
            if let Some(bytes) = value {
                assert!(i.into.cap >= bytes.len() && i.into.spans_cap >= 1);
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), i.into.buf, bytes.len());
                i.into.spans.write(ItemSpan {
                    key: ABSENT_SPAN.key,
                    value: Span {
                        offset: 0,
                        len: bytes.len() as u32,
                    },
                });
                answer.value = busbar_contract::abi::host::service::FOUND;
                answer.len = bytes.len() as u64;
                answer.items = 1;
            } else {
                answer.value = busbar_contract::abi::host::service::ABSENT;
            }
        }
        out.write(answer);
        raw
    }
}
#[allow(unsafe_code)]
extern "C" fn listing_list(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: installed only in records_list. Text borrows are confined to this call. SDK-owned
    // byte/span regions are exclusive and both capacities are checked before copying.
    unsafe {
        let i = &*input.cast::<RecordsListIn>();
        let kind = std::str::from_utf8(std::slice::from_raw_parts(i.kind.ptr, i.kind.len)).unwrap();
        let prefix = if i.prefix.len == 0 {
            ""
        } else {
            std::str::from_utf8(std::slice::from_raw_parts(i.prefix.ptr, i.prefix.len)).unwrap()
        };
        let rows: Vec<_> = LISTING.with(|s| {
            s.borrow()
                .rows
                .iter()
                .filter(|((k, key), _)| k == kind && key.starts_with(prefix))
                .map(|((_, key), value)| (key.clone(), value.clone()))
                .collect()
        });
        let mut bytes = Vec::new();
        let mut spans = Vec::new();
        for (key, value) in rows {
            let key_at = bytes.len();
            bytes.extend_from_slice(key.as_bytes());
            let value_at = bytes.len();
            bytes.extend_from_slice(&value);
            spans.push(ItemSpan {
                key: Span {
                    offset: key_at as u32,
                    len: key.len() as u32,
                },
                value: Span {
                    offset: value_at as u32,
                    len: value.len() as u32,
                },
            });
        }
        assert!(i.into.cap >= bytes.len() && i.into.spans_cap >= spans.len());
        if !bytes.is_empty() {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), i.into.buf, bytes.len());
        }
        if !spans.is_empty() {
            std::ptr::copy_nonoverlapping(spans.as_ptr(), i.into.spans, spans.len());
        }
        let raw = RawOutcome::of(Outcome::Ready);
        out.write(ServiceOut {
            size: std::mem::size_of::<ServiceOut>() as u32,
            outcome: raw,
            len: bytes.len() as u64,
            items: spans.len() as u64,
            ..ServiceOut::ZERO
        });
        raw
    }
}
#[allow(unsafe_code)]
extern "C" fn listing_claim(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    let raw = RawOutcome::of(Outcome::Ready);
    // SAFETY: installed only in records_claim; SDK lends an exclusive complete ServiceOut.
    unsafe {
        out.write(ServiceOut {
            size: std::mem::size_of::<ServiceOut>() as u32,
            outcome: raw,
            value: busbar_contract::abi::host::service::CLAIM_WON,
            ..ServiceOut::ZERO
        });
    }
    raw
}

// One concrete iteration of the actual listing algorithm and its acknowledged receipt.
fn listing_step(plane: &A2aDoor) -> Outcome {
    let host = plane.host.as_ref().unwrap();
    let journal = plane
        .units
        .with(&1, |u| u.unwrap().pass.publication.clone());
    let mut extensions = busbar_contract::abi::sdk::plane::conditional::encode_capability(
        busbar_contract::abi::sdk::plane::conditional::Capability {
            ticket: TICKET,
            epoch: 1,
        },
    );
    extensions.extend(LISTING.with(|s| std::mem::take(&mut s.borrow_mut().receipt)));
    journal.enter(TICKET, &extensions).unwrap();
    let section = plane
        .units
        .with(&1, |u| u.unwrap().section.clone())
        .unwrap();
    let mut via = Via::new(host, plane.services, TICKET, 0, &plane.grown).publishing(&journal);
    let mut writes = Vec::new();
    let setup = LISTING.with(|s| s.borrow().fail_task);
    let result = if setup {
        let envelope =
            serde_json::json!({"method":"GetTaskPushNotificationConfig","params":{"taskId":"t1"}});
        mirror_flight(
            plane,
            TICKET,
            &mut via,
            (crate::mirror::method::GET_PUSH_CONFIG, "1.0"),
            &envelope,
            ("a11ce", "planner"),
            (Some(&section), 0, 100),
        )
        .map(|_| ())
    } else {
        refresh_listed(
            plane,
            TICKET,
            1,
            &mut via,
            ("a11ce", "planner"),
            (Some(&section), 0, 100, "1.0"),
            &mut writes,
        )
    };
    assert!(
        writes.is_empty(),
        "conditional records never escape as ordinary writes"
    );
    if result == Err(Halt::Pending) {
        let receipt = crate::conditional_publication::fixture::receipt(&journal, |request| {
            use busbar_contract::abi::sdk::plane::conditional::RecordMutation;
            use busbar_contract::abi::sdk::store::conditional::{Decision, Expected};
            LISTING.with(|state| {
                let mut state = state.borrow_mut();
                for predicate in &request.candidate.predicates {
                    let key = String::from_utf8(predicate.key.clone()).unwrap();
                    let kind = crate::records::HELD_KINDS[predicate.kind as usize].to_string();
                    let actual = state.rows.get(&(kind, key));
                    assert!(match &predicate.expected {
                        Expected::Absent => actual.is_none(),
                        Expected::Bytes(value) => actual == Some(value),
                    });
                }
                for mutation in &request.candidate.mutations {
                    if let RecordMutation::Put { kind, key, value } = mutation {
                        let kind = crate::records::HELD_KINDS[*kind as usize].to_string();
                        state.committed.insert(
                            (kind, String::from_utf8(key.clone()).unwrap()),
                            value.clone(),
                        );
                    } else {
                        panic!("listing moves only put task rows");
                    }
                }
                state.publications += 1;
            });
            Decision::Applied
        });
        LISTING.with(|s| {
            let mut s = s.borrow_mut();
            s.receipt = receipt;
            s.pending_entries += 1;
        });
        return Outcome::Pending;
    }
    let failed = result.is_err();

    crate::push_door::apply_publication(plane, &journal);
    let tokens = ["t1", "t2"]
        .iter()
        .map(|id| {
            plane
                .tokens
                .claim(&format!("{id}.{}", crate::push::hex(b"signature")))
                .is_some()
        })
        .collect();
    let delivery = plane.deliveries.next_due(0);
    LISTING.with(|s| {
        let mut s = s.borrow_mut();
        s.failed = failed;
        s.writes = writes.len();
        s.tokens = tokens;
        s.delivery = delivery.is_some();
        s.first_delivery = delivery.as_ref().map(|delivery| {
            (
                delivery.task_id.clone(),
                delivery.url.clone(),
                delivery.unresolved.is_some(),
            )
        });
    });
    Outcome::Ready
}

fn listing_fixture(fail_second_config: bool, fail_task: bool) {
    LISTING.with(|s| {
        let mut fixture = ListingHost {
            fail_second_config,
            fail_task,
            ..ListingHost::default()
        };
        for id in ["t1", "t2"] {
            let mut row = crate::tasks::tests::row(id, 100);
            row.principal = "a11ce".into();
            row.agent_id = "planner".into();
            fixture.rows.insert(
                (
                    crate::records::KIND_TASK.into(),
                    tasks::task_key("a11ce", id),
                ),
                serde_json::to_vec(&tasks::HeldTask { row, next_seq: 1 }).unwrap(),
            );
            let cfg = local::PushConfig {
                id: "config".into(),
                url: format!("https://receiver.example/{id}"),
                authentication: None,
                version: "1.0".into(),
            };
            fixture.rows.insert(
                (
                    crate::records::KIND_PUSH_CONFIG.into(),
                    tasks::task_key("a11ce", id),
                ),
                serde_json::to_vec(&cfg).unwrap(),
            );
        }
        for (key, active) in [("active/v1", 2), ("1/a11ce", 2)] {
            fixture.rows.insert(
                (crate::records::KIND_TASK_QUOTA.into(), key.into()),
                format!(r#"{{"version":1,"epoch":1,"active":{active}}}"#).into_bytes(),
            );
        }
        *s.borrow_mut() = fixture;
    });
}
#[allow(unsafe_code)]
fn drive_listing() -> Vec<(tracing::Level, String)> {
    let slots = HostSlots {
        size: std::mem::size_of::<HostSlots>() as u32,
        slots: busbar_contract::abi::host::service::SERVICES,
        records_get: Some(listing_get),
        records_list: Some(listing_list),
        records_claim: Some(listing_claim),
        ..zeroed()
    };
    let tables = HostTables {
        services: &slots,
        ..unarmed_task_services()
    };
    // SAFETY: the complete table and advertised immutable slot prefix are readable here. SDK
    // snapshots copy the slots; static callbacks use only the current thread's LISTING state.
    let host = unsafe { Host::from_raw(&tables) };
    // SAFETY: same advertised readable prefix and static domain callbacks as above.
    let services = unsafe { Services::from_raw(&tables) }.unwrap();
    let plane = A2aDoor::listing_lifecycle_fixture(host, services);
    let doc = serde_json::json!({"jsonrpc":"2.0","id":"busbar-originated","result":{"tasks":[
        {"id":"backend-t1","status":{"state":"TASK_STATE_COMPLETED"}},
        {"id":"backend-t2","status":{"state":"TASK_STATE_COMPLETED"}}]}});
    plane.on_unit(1, |u| {
        u.pass.listed = Some((
            1,
            crate::binding::Binding::JsonRpc,
            Some((200, serde_json::to_vec(&doc).unwrap().into())),
        ))
    });
    let (send, receive) = std::sync::mpsc::channel();
    tracing::subscriber::with_default(crate::tests::capture::Capture(send), || {
        for _ in 0..10 {
            let outcome = listing_step(&plane);
            if outcome == Outcome::Ready {
                return;
            }
            assert_eq!(outcome, Outcome::Pending);
        }
        panic!("listing did not finish its bounded observation/publication sequence");
    });
    receive.try_iter().collect()
}

#[test]
fn a_late_listing_config_failure_keeps_earlier_applied_moves_and_defers_missing_authority() {
    listing_fixture(true, false);
    drive_listing();
    LISTING.with(|s| {
        let s = s.borrow();
        assert!(s.failed);
        assert_eq!(s.writes, 0);
        assert_eq!(s.publications, 2);
        assert_eq!(s.pending_entries, 4);
        assert!(s.config_reads.iter().any(|key| key == "a11ce/t1"));
        assert!(s.config_reads.iter().any(|key| key == "a11ce/t2"));
        assert!(s.delivery, "the earlier acknowledged notification survives");
        assert_eq!(
            s.first_delivery,
            Some(("t1".into(), "https://receiver.example/t1".into(), false))
        );
        assert_eq!(
            s.tokens,
            [false, false],
            "both acknowledged rows are terminal"
        );
    });
}
#[test]
fn the_success_control_reads_both_configs_and_acknowledges_actual_task_transitions() {
    listing_fixture(false, false);
    drive_listing();
    LISTING.with(|s| {
        let s = s.borrow();
        assert!(!s.failed);
        assert_eq!(s.writes, 0);
        assert_eq!(s.publications, 2);
        assert_eq!(s.pending_entries, 4);
        assert!(s.delivery);
        assert_eq!(s.tokens, [false, false]);
        for id in ["t1", "t2"] {
            let raw = &s.committed[&(
                crate::records::KIND_TASK.into(),
                tasks::task_key("a11ce", id),
            )];
            let held: tasks::HeldTask = serde_json::from_slice(raw).unwrap();
            assert_eq!(held.row.state, "completed");
        }
    });
}
#[test]
fn a_real_mirror_setup_read_failure_is_reported_without_exposing_request_material() {
    listing_fixture(false, true);

    let events = drive_listing();
    LISTING.with(|s| assert!(s.borrow().failed));
    assert!(
        events
            .iter()
            .any(|(level, text)| *level == tracing::Level::WARN
                && text.contains("setup")
                && text.contains("planner")),
        "{events:?}"
    );
    assert!(!events
        .iter()
        .any(|(_, text)| text.contains("https://") || text.contains("authentication")));
}

#[test]
#[allow(unsafe_code)]
fn a_full_book_refuses_an_untracked_handle_before_any_host_issue_even_on_reentry() {
    let unserved = unarmed_task_services();
    // SAFETY: complete immutable table advertises the full static unarmed service prefix.
    let host = unsafe { Host::from_raw(&unserved) };
    // SAFETY: same readable static service prefix; callbacks are None and borrow no state.
    let services = unsafe { Services::from_raw(&unserved) };
    let grown = Keyed::new();
    let held = Via::new(&host, services, ticket(2), 0, &grown);
    for seq in 0..GROWN_MAX as u32 {
        let _ = held.grow(handle(ticket(2), seq), 2, 0);
    }
    let mut host_calls = 0;

    for _ in 0..2 {
        let mut via = Via::new(&host, services, ticket(1), 0, &grown);
        let result = via.issue((1, 0), |_, _, buf, _| {
            host_calls += 1;
            if buf.len() < 2 {
                Poll::Ready(Err(ServiceError::Short { bytes: 2, items: 0 }))
            } else {
                Poll::Ready(Ok(()))
            }
        });
        assert!(matches!(result, Err(Halt::Failed(_))));
        assert_eq!(
            via.issued(),
            0,
            "capacity refusal crossed no service handle"
        );
    }
    assert_eq!(host_calls, 0);
}

#[test]
#[allow(unsafe_code)]
fn completed_records_calls_release_reservations_instead_of_consuming_the_growth_bound() {
    let unserved = unarmed_task_services();
    // SAFETY: complete immutable table advertises the full static unarmed service prefix.
    let host = unsafe { Host::from_raw(&unserved) };
    // SAFETY: same readable static service prefix; callbacks are None and borrow no state.
    let services = unsafe { Services::from_raw(&unserved) };
    let grown = Keyed::new();
    let mut via = Via::new(&host, services, ticket(1), 0, &grown);
    for _ in 0..GROWN_MAX * 2 {
        assert_eq!(via.issue((1, 0), |_, _, _, _| Poll::Ready(Ok(()))), Ok(()));
    }
    assert_eq!(
        grown.len(),
        0,
        "only pending reservations and genuine SHORT sizes stay held"
    );
}

#[test]
#[allow(unsafe_code)]
fn an_already_pending_handle_can_grow_at_capacity_without_forgetting_another_ticket() {
    let unserved = unarmed_task_services();
    // SAFETY: complete immutable table advertises the full static unarmed service prefix.
    let host = unsafe { Host::from_raw(&unserved) };
    // SAFETY: same readable static service prefix; callbacks are None and borrow no state.
    let services = unsafe { Services::from_raw(&unserved) };
    let grown = Keyed::new();
    let mut first = Via::new(&host, services, ticket(1), 0, &grown);
    let pending: Result<(), Halt> = first.issue((1, 0), |_, _, _, _| Poll::Pending);
    assert_eq!(pending, Err(Halt::Pending));
    let other = Via::new(&host, services, ticket(3), 0, &grown);
    let _ = other.grow(handle(ticket(3), 0), 2, 0);
    let filling = Via::new(&host, services, ticket(2), 0, &grown);
    for seq in 0..(GROWN_MAX - 1) as u32 {
        let _ = filling.grow(handle(ticket(2), seq), 1, 0);
    }
    let mut resumed = Via::new(&host, services, ticket(1), 0, &grown);
    assert_eq!(
        resumed.issue((1, 0), |_, _, buf, _| {
            if buf.len() < 2 {
                Poll::Ready(Err(ServiceError::Short { bytes: 2, items: 0 }))
            } else {
                Poll::Ready(Ok(()))
            }
        }),
        Ok(())
    );
    let mut other = Via::new(&host, services, ticket(3), 0, &grown);
    assert_eq!(
        other.issue((1, 0), |_, _, buf, _| {
            assert_eq!(
                buf.len(),
                2,
                "the accepted pending handle could grow without evicting this ticket"
            );
            Poll::Ready(Ok(()))
        }),
        Ok(())
    );
}
