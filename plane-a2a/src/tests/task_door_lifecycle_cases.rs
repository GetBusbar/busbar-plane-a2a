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
fn a_full_sizes_book_never_forgets_a_pending_tickets_short_answer() {
    let fake: &'static FakeHost = Box::leak(Box::new(FakeHost::new()));
    let tables = fake.lent();
    let host = Host::of(&tables);
    let grown = Keyed::new();
    let first = ticket(1);
    let mut via = Via::new(&host, Services::of(&tables), first, 0, &grown);
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
    let other = Via::new(&host, Services::of(&tables), ticket(2), 0, &grown);
    for seq in 0..GROWN_MAX as u32 {
        let _ = other.grow(handle(ticket(2), seq), 1, 0);
    }
    let mut resumed = Via::new(&host, Services::of(&tables), first, 0, &grown);
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

use busbar_contract::abi::host::service::{RecordsClaimIn, RecordsGetIn, RecordsListIn};
use busbar_contract::abi::mechanism::call::OutHead;
use busbar_contract::abi::mechanism::lifecycle::{DriveIn, OpenIn, OpenOut};
use busbar_contract::abi::sdk::test_support::fake::{self, FakeService, ServiceCall};
use busbar_contract::abi::sdk::test_support::{reply, test_in::TestIn, zeroed, DoorView};
use busbar_contract::abi::sdk::{Safe, SafeSlot};
use std::cell::RefCell;
use std::collections::BTreeMap;

#[derive(Default)]
struct ListingHost {
    rows: BTreeMap<(String, String), Vec<u8>>,
    fail_task: bool,
    fail_second_config: bool,
    config_reads: Vec<String>,
    failed: bool,
    writes: usize,
    delivery: bool,
    tokens: Vec<bool>,
}
thread_local! { static LISTING: RefCell<ListingHost> = RefCell::new(ListingHost::default()); }

struct Get;
impl FakeService for Get {
    type In = RecordsGetIn;
    fn serve(call: &mut ServiceCall<Self::In>) -> Outcome {
        let kind = call.text(|i| &i.kind).to_string();
        let key = call.text(|i| &i.key).to_string();
        let (failed, value) = LISTING.with(|s| {
            let mut s = s.borrow_mut();
            if kind == crate::records::KIND_PUSH_CONFIG {
                s.config_reads.push(key.clone());
            }
            let failed = (s.fail_task && kind == crate::records::KIND_TASK)
                || (s.fail_second_config
                    && kind == crate::records::KIND_PUSH_CONFIG
                    && key.ends_with("/t2"));
            (failed, s.rows.get(&(kind, key)).cloned())
        });
        if failed {
            return Outcome::Failed;
        }
        if let Some(bytes) = value {
            assert!(call.fill(
                |i| &i.into,
                &bytes,
                &[ItemSpan {
                    key: ABSENT_SPAN.key,
                    value: Span {
                        offset: 0,
                        len: bytes.len() as u32
                    }
                }]
            ));
            call.set_value(busbar_contract::abi::host::service::FOUND);
        } else {
            call.set_value(busbar_contract::abi::host::service::ABSENT);
        }
        Outcome::Ready
    }
}
struct List;
impl FakeService for List {
    type In = RecordsListIn;
    fn serve(call: &mut ServiceCall<Self::In>) -> Outcome {
        let kind = call.text(|i| &i.kind);
        let prefix = call.text(|i| &i.prefix);
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
        assert!(call.fill(|i| &i.into, &bytes, &spans));
        Outcome::Ready
    }
}
struct Claim;
impl FakeService for Claim {
    type In = RecordsClaimIn;
    fn serve(call: &mut ServiceCall<Self::In>) -> Outcome {
        call.set_value(busbar_contract::abi::host::service::CLAIM_WON);
        Outcome::Ready
    }
}

mod listing_probe {
    use super::*;
    pub struct Open;
    impl SafeSlot for Open {
        type In = OpenIn;
        type Out = OpenOut;
        type State = A2aDoor;
        fn call(
            instance: Instance<'_, A2aDoor>,
            input: Lent<'_, Self::In>,
            _: Out<'_, Self::Out>,
        ) -> Outcome {
            let tables = input.host().unwrap();
            let plane = A2aDoor::listing_lifecycle_fixture(
                Host::of(&tables),
                Services::of(&tables).unwrap(),
            );
            let doc = serde_json::json!({"jsonrpc":"2.0","id":"busbar-originated","result":{"tasks":[
                {"id":"backend-t1","status":{"state":"TASK_STATE_COMPLETED"}},
                {"id":"backend-t2","status":{"state":"TASK_STATE_COMPLETED"}}]}});
            plane.on_unit(1, |u| {
                u.pass.listed = Some((1, Some((200, serde_json::to_vec(&doc).unwrap()))))
            });
            instance.open(plane);
            Outcome::Ready
        }
    }
    pub struct Drive;
    impl SafeSlot for Drive {
        type In = DriveIn;
        type Out = OutHead;
        type State = A2aDoor;
        fn call(
            instance: Instance<'_, A2aDoor>,
            _: Lent<'_, Self::In>,
            _: Out<'_, Self::Out>,
        ) -> Outcome {
            let plane = instance.get().unwrap();
            let host = plane.host.as_ref().unwrap();
            let section = plane
                .units
                .with(&1, |u| u.unwrap().section.clone())
                .unwrap();
            let mut via = Via::new(host, plane.services, instance.ticket(), 0, &plane.grown);
            let mut writes = Vec::new();
            let setup = LISTING.with(|s| s.borrow().fail_task);
            let failed = if setup {
                let envelope = serde_json::json!({"method":"GetTaskPushNotificationConfig","params":{"taskId":"t1"}});
                matches!(
                    mirror_flight(
                        plane,
                        &instance,
                        &mut via,
                        (crate::mirror::method::GET_PUSH_CONFIG, "1.0"),
                        &envelope,
                        ("a11ce", "planner"),
                        (Some(&section), 0, 100)
                    ),
                    Err(Halt::Failed(_))
                )
            } else {
                matches!(
                    refresh_listed(
                        plane,
                        &instance,
                        1,
                        &mut via,
                        ("a11ce", "planner"),
                        (Some(&section), 0, 100, "1.0"),
                        &mut writes
                    ),
                    Err(Halt::Failed(_))
                )
            };
            let tokens = ["t1", "t2"]
                .iter()
                .map(|id| {
                    plane
                        .tokens
                        .claim(&format!("{id}.{}", crate::push::hex(b"signature")))
                        .is_some()
                })
                .collect();
            let delivery = plane.deliveries.next_due(0).is_some();
            LISTING.with(|s| {
                let mut s = s.borrow_mut();
                s.failed = failed;
                s.writes = writes.len();
                s.tokens = tokens;
                s.delivery = delivery;
            });
            Outcome::Ready
        }
    }
    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::export::Ops,
        statement: busbar_contract::abi::sdk::door::statement("task-listing-probe", "0", 4),
        lifecycle: { open: Safe<Open>, drive: Safe<Drive> },
    }
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
        *s.borrow_mut() = fixture;
    });
}
fn drive_listing() {
    let fake = FakeHost::new()
        .serve(fake::host::RECORDS_GET, Get)
        .serve(fake::host::RECORDS_LIST, List)
        .serve(fake::host::RECORDS_CLAIM, Claim);
    let view = DoorView::of(listing_probe::MACRO_DOOR);
    let open = fake.lend_in(TestIn::<OpenIn>::new());
    let mut opened = reply::call_hosted_in(
        view.op::<busbar_contract::abi::export::Ops>(|t| &t.head.open)
            .unwrap(),
        None,
        &open,
        zeroed::<OpenOut>(),
    );
    assert_eq!(opened.outcome, Outcome::Ready);
    let instance = opened.take_instance().unwrap();
    let input = TestIn::<DriveIn>::new().set(|i| &i.head.ticket, TICKET);
    let result = reply::call_in(
        view.op::<busbar_contract::abi::export::Ops>(|t| &t.head.drive)
            .unwrap(),
        Some(&instance),
        &input,
        zeroed::<OutHead>(),
    );
    assert_eq!(result.outcome, Outcome::Ready);
}

#[test]
fn a_late_listing_config_failure_cannot_queue_or_invalidate_an_earlier_tasks_token() {
    listing_fixture(true, false);
    drive_listing();
    LISTING.with(|s| {
        let s = s.borrow();
        assert!(s.failed);
        assert!(
            s.writes > 0,
            "both state transitions were staged before the injected late config failure"
        );
        assert_eq!(s.config_reads, ["a11ce/t1", "a11ce/t2"]);
        assert!(!s.delivery);
        assert_eq!(s.tokens, [true, true]);
    });
}
#[test]
fn the_success_control_reads_both_configs_and_stages_the_actual_task_transitions() {
    listing_fixture(false, false);
    drive_listing();
    LISTING.with(|s| {
        let s = s.borrow();
        assert!(!s.failed);
        assert!(s.writes > 0);
        assert_eq!(s.config_reads, ["a11ce/t1", "a11ce/t2"]);
    });
}
#[test]
fn a_real_mirror_setup_read_failure_is_reported_without_exposing_request_material() {
    listing_fixture(false, true);
    let (send, receive) = std::sync::mpsc::channel();
    tracing::subscriber::with_default(crate::tests::capture::Capture(send), drive_listing);
    LISTING.with(|s| assert!(s.borrow().failed));
    let events: Vec<_> = receive.try_iter().collect();
    assert!(
        events
            .iter()
            .any(|(level, words)| *level == tracing::Level::WARN
                && words.contains("setup")
                && words.contains("planner")),
        "{events:?}"
    );
    assert!(!events
        .iter()
        .any(|(_, words)| words.contains("https://") || words.contains("authentication")));
}

#[test]
fn a_full_book_refuses_an_untracked_handle_before_any_host_issue_even_on_reentry() {
    let fake: &'static FakeHost = Box::leak(Box::new(FakeHost::new()));
    let tables = fake.lent();
    let host = Host::of(&tables);
    let grown = Keyed::new();
    let held = Via::new(&host, Services::of(&tables), ticket(2), 0, &grown);
    for seq in 0..GROWN_MAX as u32 {
        let _ = held.grow(handle(ticket(2), seq), 2, 0);
    }
    let mut host_calls = 0;
    // The first error answer may itself have short output buffers; its re-entry must still
    // refuse BEFORE issuing an untracked host handle, rather than asking it SHORT twice.
    for _ in 0..2 {
        let mut via = Via::new(&host, Services::of(&tables), ticket(1), 0, &grown);
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
fn completed_records_calls_release_reservations_instead_of_consuming_the_growth_bound() {
    let fake: &'static FakeHost = Box::leak(Box::new(FakeHost::new()));
    let tables = fake.lent();
    let host = Host::of(&tables);
    let grown = Keyed::new();
    let mut via = Via::new(&host, Services::of(&tables), ticket(1), 0, &grown);
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
fn an_already_pending_handle_can_grow_at_capacity_without_forgetting_another_ticket() {
    let fake: &'static FakeHost = Box::leak(Box::new(FakeHost::new()));
    let tables = fake.lent();
    let host = Host::of(&tables);
    let grown = Keyed::new();
    let mut first = Via::new(&host, Services::of(&tables), ticket(1), 0, &grown);
    let pending: Result<(), Halt> = first.issue((1, 0), |_, _, _, _| Poll::Pending);
    assert_eq!(pending, Err(Halt::Pending));
    let other = Via::new(&host, Services::of(&tables), ticket(3), 0, &grown);
    let _ = other.grow(handle(ticket(3), 0), 2, 0);
    let filling = Via::new(&host, Services::of(&tables), ticket(2), 0, &grown);
    for seq in 0..(GROWN_MAX - 1) as u32 {
        let _ = filling.grow(handle(ticket(2), seq), 1, 0);
    }
    let mut resumed = Via::new(&host, Services::of(&tables), ticket(1), 0, &grown);
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
    let mut other = Via::new(&host, Services::of(&tables), ticket(3), 0, &grown);
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
