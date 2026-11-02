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
    let unserved = no_task_services();
    let tables = &unserved;
    let host = Host::of(tables);
    let grown = Keyed::new();
    let first = ticket(1);
    let mut via = Via::new(&host, Services::of(tables), first, 0, &grown);
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
    let other = Via::new(&host, Services::of(tables), ticket(2), 0, &grown);
    for seq in 0..GROWN_MAX as u32 {
        let _ = other.grow(handle(ticket(2), seq), 1, 0);
    }
    let mut resumed = Via::new(&host, Services::of(tables), first, 0, &grown);
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
use busbar_contract::abi::mechanism::lifecycle::{slot as life, DriveIn, OpenIn, OpenOut};
use busbar_contract::abi::sdk::{Safe, SafeSlot};
use busbar_test_kit::test_support::fake::{self, FakeHost, FakeService, ServiceCall};
use busbar_test_kit::test_support::{reply, test_in::TestIn, zeroed, DoorView};
use std::cell::RefCell;
use std::collections::BTreeMap;

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

struct Get;
impl FakeService for Get {
    type In = RecordsGetIn;
    fn serve(call: &mut ServiceCall<Self::In>) -> Outcome {
        let kind = call.text(|i| &i.kind).to_string();
        let key = call.text(|i| &i.key).to_string();
        let (failed, value) = LISTING.with(|s| {
            let mut s = s.borrow_mut();
            if kind == crate::records::KIND_PUSH_CONFIG
                && s.read_handles.insert(call.input().head.handle.seq)
            {
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

    macro_rules! fixture_slot {
        ($name:ident, $input:ty, $output:ty, $outcome:expr) => {
            pub struct $name;
            impl SafeSlot for $name {
                type In = $input;
                type Out = $output;
                type State = A2aDoor;
                fn call(
                    _: Instance<'_, A2aDoor>,
                    _: Lent<'_, Self::In>,
                    _: Out<'_, Self::Out>,
                ) -> Outcome {
                    $outcome
                }
            }
        };
    }
    use busbar_contract::abi::mechanism::call::InHead;
    use busbar_contract::abi::mechanism::lifecycle::{
        CancelIn, CancelOut, GenIn, RefreshIn, ReleaseIn, TickIn, TickOut, ValidateIn,
    };
    fixture_slot!(Validate, ValidateIn, OutHead, Outcome::Refused);
    fixture_slot!(Refresh, RefreshIn, OutHead, Outcome::Refused);
    fixture_slot!(Retire, GenIn, OutHead, Outcome::Refused);
    fixture_slot!(Tick, TickIn, TickOut, Outcome::Refused);
    fixture_slot!(Cancel, CancelIn, CancelOut, Outcome::Refused);
    fixture_slot!(Release, ReleaseIn, OutHead, Outcome::Refused);
    fixture_slot!(Close, InHead, OutHead, Outcome::Ready);
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
            let plane =
                A2aDoor::listing_lifecycle_fixture(Host::of(tables), Services::of(tables).unwrap());
            let doc = serde_json::json!({"jsonrpc":"2.0","id":"busbar-originated","result":{"tasks":[
                {"id":"backend-t1","status":{"state":"TASK_STATE_COMPLETED"}},
                {"id":"backend-t2","status":{"state":"TASK_STATE_COMPLETED"}}]}});
            plane.on_unit(1, |u| {
                u.pass.listed = Some((
                    1,
                    crate::binding::Binding::JsonRpc,
                    Some((200, serde_json::to_vec(&doc).unwrap())),
                ))
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
            let journal = plane
                .units
                .with(&1, |u| u.unwrap().pass.publication.clone());
            let mut extensions = busbar_contract::abi::sdk::plane::conditional::encode_capability(
                busbar_contract::abi::sdk::plane::conditional::Capability {
                    ticket: instance.ticket(),
                    epoch: 1,
                },
            );
            extensions.extend(LISTING.with(|s| std::mem::take(&mut s.borrow_mut().receipt)));
            journal.enter(instance.ticket(), &extensions).unwrap();
            let section = plane
                .units
                .with(&1, |u| u.unwrap().section.clone())
                .unwrap();
            let mut via = Via::new(host, plane.services, instance.ticket(), 0, &plane.grown)
                .publishing(&journal);
            let mut writes = Vec::new();
            let setup = LISTING.with(|s| s.borrow().fail_task);
            let result = if setup {
                let envelope = serde_json::json!({"method":"GetTaskPushNotificationConfig","params":{"taskId":"t1"}});
                mirror_flight(
                    plane,
                    &instance,
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
                    &instance,
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
                let receipt =
                    crate::conditional_publication::fixture::receipt(&journal, |request| {
                        use busbar_contract::abi::sdk::plane::conditional::RecordMutation;
                        use busbar_contract::abi::sdk::store::conditional::{Decision, Expected};
                        LISTING.with(|state| {
                            let mut state = state.borrow_mut();
                            for predicate in &request.candidate.predicates {
                                let key = String::from_utf8(predicate.key.clone()).unwrap();
                                let kind =
                                    crate::records::HELD_KINDS[predicate.kind as usize].to_string();
                                let actual = state.rows.get(&(kind, key));
                                assert!(match &predicate.expected {
                                    Expected::Absent => actual.is_none(),
                                    Expected::Bytes(value) => actual == Some(value),
                                });
                            }
                            for mutation in &request.candidate.mutations {
                                if let RecordMutation::Put { kind, key, value } = mutation {
                                    let kind =
                                        crate::records::HELD_KINDS[*kind as usize].to_string();
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
    }
    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::export::Ops,
        statement: busbar_contract::abi::sdk::door::statement("task-listing-probe", "0", 4),
        lifecycle: {
            validate: Safe<Validate>,
            open: Safe<Open>,
            refresh: Safe<Refresh>,
            retire: Safe<Retire>,
            tick: Safe<Tick>,
            drive: Safe<Drive>,
            cancel: Safe<Cancel>,
            release: Safe<Release>,
            close: Safe<Close>,
        },
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
fn drive_listing() -> Vec<reply::DiagCopy> {
    struct Opened<'h> {
        instance: Option<reply::Instance<'h>>,
        close: busbar_test_kit::test_support::ViewOp,
    }
    impl Drop for Opened<'_> {
        fn drop(&mut self) {
            if let Some(instance) = self.instance.take() {
                let _ = reply::close_in(
                    self.close,
                    instance,
                    &TestIn::<busbar_contract::abi::mechanism::call::InHead>::new()
                        .set(|i| &i.op, life::CLOSE),
                    zeroed::<OutHead>(),
                );
            }
        }
    }
    let fake = FakeHost::new()
        .serve(fake::host::RECORDS_GET, Get)
        .serve(fake::host::RECORDS_LIST, List)
        .serve(fake::host::RECORDS_CLAIM, Claim);
    let view = DoorView::of(listing_probe::MACRO_DOOR);
    let open = fake.lend_in(TestIn::<OpenIn>::new().set(|i| &i.head.op, life::OPEN));
    let mut opened = reply::call_hosted_in(
        view.op::<busbar_contract::abi::export::Ops>(|t| &t.head.open)
            .unwrap(),
        None,
        &open,
        zeroed::<OpenOut>(),
    );
    assert_eq!(opened.outcome, Outcome::Ready, "{opened:?}");
    let mut diagnostics = opened.envelope.diags.clone();
    let instance = Opened {
        instance: opened.take_instance(),
        close: view
            .op::<busbar_contract::abi::export::Ops>(|t| &t.head.close)
            .unwrap(),
    };
    assert!(instance.instance.is_some());
    let input = TestIn::<DriveIn>::new()
        .set(|i| &i.head.op, life::DRIVE)
        .set(|i| &i.head.ticket, TICKET);
    for _ in 0..10 {
        let result = reply::call_in(
            view.op::<busbar_contract::abi::export::Ops>(|t| &t.head.drive)
                .unwrap(),
            instance.instance.as_ref(),
            &input,
            zeroed::<OutHead>(),
        );
        diagnostics.extend(result.envelope.diags);
        if result.outcome == Outcome::Ready {
            return diagnostics;
        }
        assert_eq!(result.outcome, Outcome::Pending);
    }
    panic!("listing did not finish its bounded observation/publication sequence");
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
        events.iter().any(|event| event.severity
            == busbar_contract::abi::mechanism::call::SEVERITY_WARN
            && event.text.contains("setup")
            && event.text.contains("planner")),
        "{events:?}"
    );
    assert!(!events
        .iter()
        .any(|event| event.text.contains("https://") || event.text.contains("authentication")));
}

#[test]
fn a_full_book_refuses_an_untracked_handle_before_any_host_issue_even_on_reentry() {
    let unserved = no_task_services();
    let tables = &unserved;
    let host = Host::of(tables);
    let grown = Keyed::new();
    let held = Via::new(&host, Services::of(tables), ticket(2), 0, &grown);
    for seq in 0..GROWN_MAX as u32 {
        let _ = held.grow(handle(ticket(2), seq), 2, 0);
    }
    let mut host_calls = 0;

    for _ in 0..2 {
        let mut via = Via::new(&host, Services::of(tables), ticket(1), 0, &grown);
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
    let unserved = no_task_services();
    let tables = &unserved;
    let host = Host::of(tables);
    let grown = Keyed::new();
    let mut via = Via::new(&host, Services::of(tables), ticket(1), 0, &grown);
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
    let unserved = no_task_services();
    let tables = &unserved;
    let host = Host::of(tables);
    let grown = Keyed::new();
    let mut first = Via::new(&host, Services::of(tables), ticket(1), 0, &grown);
    let pending: Result<(), Halt> = first.issue((1, 0), |_, _, _, _| Poll::Pending);
    assert_eq!(pending, Err(Halt::Pending));
    let other = Via::new(&host, Services::of(tables), ticket(3), 0, &grown);
    let _ = other.grow(handle(ticket(3), 0), 2, 0);
    let filling = Via::new(&host, Services::of(tables), ticket(2), 0, &grown);
    for seq in 0..(GROWN_MAX - 1) as u32 {
        let _ = filling.grow(handle(ticket(2), seq), 1, 0);
    }
    let mut resumed = Via::new(&host, Services::of(tables), ticket(1), 0, &grown);
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
    let mut other = Via::new(&host, Services::of(tables), ticket(3), 0, &grown);
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
