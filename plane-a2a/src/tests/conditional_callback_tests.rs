// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::records::{KIND_TASK, KIND_TASK_EVENT};

const TICKET: Ticket = Ticket {
    slot: 19,
    generation: 3,
};
const KEY: &str = "aa/t1";
fn capability() -> wire::Capability {
    wire::Capability {
        ticket: TICKET,
        epoch: 7,
    }
}
fn input(receipt: &[u8]) -> Vec<u8> {
    let mut bytes = wire::encode_capability(capability());
    bytes.extend_from_slice(receipt);
    bytes
}
fn observed(j: &Journal) -> ChainLife {
    assert_eq!(j.observe(3, KIND_TASK_EVENT, KEY), Err(Halt::Pending));
    let request = j.0.with_all(|all| {
        let step = &mut all.get_mut(&()).unwrap().steps[0];
        step.submitted = true;
        let Action::Observe { request, .. } = &step.action else {
            panic!("observe")
        };
        request.clone()
    });
    let life = 11_u64.to_le_bytes().to_vec();
    let receipt = wire::encode_observed(
        &request,
        &wire::ObservationResult {
            correlation: request.correlation,
            result: Ok(Expected::Bytes(life.clone())),
        },
    )
    .unwrap();
    j.enter(TICKET, &input(&receipt)).unwrap();
    assert_eq!(j.observe(3, KIND_TASK_EVENT, KEY), Ok(Some(life.clone())));
    ChainLife {
        kind: KIND_TASK_EVENT,
        scope: KEY.into(),
        expected: Some(life),
    }
}
fn publication(j: &Journal, life: &ChainLife) -> wire::Request {
    let p = Predicate {
        kind: KIND_TASK,
        key: KEY.into(),
        expected: Some(b"raw task".to_vec()),
    };
    let writes = [
        Write {
            kind: KIND_TASK,
            key: KEY.into(),
            value: b"new task".to_vec(),
        },
        Write {
            kind: KIND_TASK_EVENT,
            key: KEY.into(),
            value: b"event".to_vec(),
        },
    ];
    assert_eq!(
        j.publish(5, &[p], &[life.clone()], &writes),
        Err(Halt::Pending)
    );
    j.0.with_all(|all| {
        let step = all
            .get_mut(&())
            .unwrap()
            .steps
            .iter_mut()
            .find(|s| s.seq == 5)
            .unwrap();
        step.submitted = true;
        let Action::Publish { request, .. } = &step.action else {
            panic!("publish")
        };
        request.clone()
    })
}

#[test]
fn indeterminate_retains_original_candidate_and_never_allows_replanning() {
    let j = Journal::default();
    j.enter(TICKET, &input(&[])).unwrap();
    let life = observed(&j);
    let original = publication(&j, &life);
    assert!(j.owns_unresolved_event(KIND_TASK_EVENT, KEY));
    let result = wire::encode_result(
        &original,
        &wire::ConditionalResult {
            correlation: original.candidate.correlation,
            decision: Err(wire::ConditionalFailure::Indeterminate),
        },
    )
    .unwrap();
    assert!(j.enter(TICKET, &input(&result)).is_err());
    assert!(j.committed_writes().is_empty());
    assert!(j.owns_unresolved_event(KIND_TASK_EVENT, KEY));
    assert!(j.observe(6, KIND_TASK_EVENT, KEY).is_err());
    j.finished();
    j.0.with(&(), |s| {
        let Action::Publish { request, .. } = &s.unwrap().steps[1].action else {
            panic!("retained")
        };
        assert_eq!(request, &original);
    });
}

#[test]
fn publication_requires_the_exact_pre_read_life_and_rejects_a_new_epoch() {
    let j = Journal::default();
    j.enter(TICKET, &input(&[])).unwrap();
    let mut life = observed(&j);
    life.expected = Some(12_u64.to_le_bytes().to_vec());
    assert!(j.publish(5, &[], &[life], &[]).is_err());
    let second = Journal::default();
    second.enter(TICKET, &input(&[])).unwrap();
    let life = observed(&second);
    publication(&second, &life);
    let other = wire::encode_capability(wire::Capability {
        epoch: 8,
        ..capability()
    });
    assert!(second.enter(TICKET, &other).is_err());
    assert!(second.committed_writes().is_empty());
}

#[test]
fn committed_metadata_is_exposed_once_and_only_after_applied() {
    let j = Journal::default();
    j.enter(TICKET, &input(&[])).unwrap();
    let life = observed(&j);
    let request = publication(&j, &life);
    assert!(j.committed_writes().is_empty());
    let result = wire::encode_result(
        &request,
        &wire::ConditionalResult {
            correlation: request.candidate.correlation,
            decision: Ok(Decision::Applied),
        },
    )
    .unwrap();
    j.enter(TICKET, &input(&result)).unwrap();
    assert!(!j.owns_unresolved_event(KIND_TASK_EVENT, KEY));
    assert_eq!(j.committed_writes().len(), 2);
    assert!(j.committed_writes().is_empty());
    assert!(j.applied_since(4, KIND_TASK_EVENT, KEY));
    assert!(!j.applied_since(6, KIND_TASK_EVENT, KEY));
}

#[test]
fn cancellation_aborts_only_an_unsubmitted_attempt() {
    let j = Journal::default();
    j.enter(TICKET, &input(&[])).unwrap();
    assert_eq!(j.observe(3, KIND_TASK_EVENT, KEY), Err(Halt::Pending));
    j.cancelled();
    j.0.with(&(), |s| assert!(s.unwrap().steps.is_empty()));
    let sent = Journal::default();
    sent.enter(TICKET, &input(&[])).unwrap();
    let life = observed(&sent);
    let original = publication(&sent, &life);
    sent.cancelled();
    sent.0.with(&(), |s| {
        let Action::Publish { request, .. } = &s.unwrap().steps[1].action else {
            panic!("retained")
        };
        assert_eq!(request, &original);
    });
}

#[test]
fn ambiguous_backend_ids_cannot_select_an_arbitrary_task_for_list_refresh() {
    let mut rows: Vec<_> = ["t1", "t2", "t3"]
        .into_iter()
        .map(|id| crate::tasks::tests::row(id, 100))
        .collect();
    for row in &mut rows {
        row.agent_id = "vendor".into();
    }
    let ids = crate::task_door::listed_backend_ids(&rows, "vendor", |id| {
        Some(if id == "t3" { "unique" } else { "shared" }.into())
    });
    assert_eq!(ids, [("unique".into(), "t3".into())].into());
    assert!(
        crate::task_door::listed_backend_ids(&rows, "other", |_| Some("shared".into())).is_empty()
    );
}

fn settlement(
    request: &wire::Request,
    decision: Result<Decision, wire::ConditionalFailure>,
) -> wire::Settlement {
    wire::Settlement {
        capability: request.capability,
        result: wire::ConditionalResult {
            correlation: request.candidate.correlation,
            decision,
        },
        request_digest: busbar_contract::abi::sdk::digest::sha256(
            &wire::encode_request(request).unwrap(),
        ),
    }
}

fn notification(journal: &Journal, seq: u32, url: &str) -> wire::Request {
    let mut row = crate::tasks::tests::row("t1", 100 + u64::from(seq));
    row.principal = "aa".into();
    let writes = [Write {
        kind: KIND_TASK,
        key: KEY.into(),
        value: serde_json::to_vec(&row).unwrap(),
    }];
    let draft = Draft {
        notify: true,
        config: Some(Ok(Some(crate::local::PushConfig {
            id: "cfg".into(),
            url: url.into(),
            authentication: None,
            version: String::new(),
        }))),
        backend: Some(format!("backend-{seq}")),
        ..Draft::default()
    };
    assert_eq!(
        journal.publish_with(seq, &[], &[], &writes, &draft),
        Err(Halt::Pending)
    );
    journal.0.with_all(|all| {
        let step = all.get_mut(&()).unwrap().steps.last_mut().unwrap();
        step.submitted = true;
        let Action::Publish { request, .. } = &step.action else {
            panic!("publication")
        };
        request.clone()
    })
}

#[test]
fn detached_settlement_keeps_original_config_and_effects_once_across_lost_ack() {
    let deliveries = crate::push::Deliveries::default();
    let journal = Journal::default();
    journal.enter(TICKET, &input(&[])).unwrap();
    let original = notification(&journal, 1, "https://original.example/hook");
    deliveries.retain_publication(&journal);
    journal.owner_dropped();
    drop(journal);
    let retained = deliveries
        .publications()
        .pop()
        .expect("book retained callback");
    let receipt = settlement(&original, Ok(Decision::Applied));
    assert!(retained.settle(&receipt).unwrap());
    let effects = retained.applied_effects();
    assert_eq!(effects.notify.len(), 1);
    assert_eq!(effects.backends.len(), 1);
    assert_eq!(
        effects.notify[0]
            .1
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap()
            .url,
        "https://original.example/hook"
    );
    retained.effects_finished(effects.owner);
    retained.offer_ack(&receipt);
    assert!(
        !retained.ack_confirmed(Some(&receipt)),
        "lost ACK keeps custody"
    );
    assert!(retained.settle(&receipt).unwrap());
    let repeated = retained.applied_effects();
    assert!(
        repeated.notify.is_empty() && repeated.backends.is_empty() && repeated.deletes.is_empty()
    );
    assert!(
        retained.enter(TICKET, &input(&[])).is_err(),
        "canceled callback stays canceled"
    );
    assert!(retained.ack_confirmed(None));
    deliveries.release_publication(&retained);
    assert!(deliveries.publications().is_empty());
}

#[test]
fn settlement_rejects_changed_identity_and_unsubmitted_candidate() {
    let journal = Journal::default();
    journal.enter(TICKET, &input(&[])).unwrap();
    let original = notification(&journal, 1, "https://original.example/hook");
    let receipt = settlement(&original, Ok(Decision::Applied));
    let mut altered = receipt.clone();
    altered.request_digest[0] ^= 1;
    assert!(!journal.settle(&altered).unwrap());
    altered = receipt.clone();
    altered.capability.epoch += 1;
    assert!(!journal.settle(&altered).unwrap());
    altered = receipt.clone();
    altered.capability.ticket.generation += 1;
    assert!(!journal.settle(&altered).unwrap());
    altered = receipt.clone();
    altered.result.correlation += 1;
    assert!(!journal.settle(&altered).unwrap());
    journal
        .0
        .with_all(|all| all.get_mut(&()).unwrap().steps[0].submitted = false);
    assert!(!journal.settle(&receipt).unwrap());
    assert!(journal.applied_effects().notify.is_empty());
}

#[test]
fn separate_publications_of_one_task_keep_separate_effects_and_config() {
    let journal = Journal::default();
    journal.enter(TICKET, &input(&[])).unwrap();
    let first = notification(&journal, 1, "https://first.example/hook");
    let result = wire::encode_result(
        &first,
        &wire::ConditionalResult {
            correlation: first.candidate.correlation,
            decision: Ok(Decision::Applied),
        },
    )
    .unwrap();
    journal.enter(TICKET, &input(&result)).unwrap();
    let second = notification(&journal, 2, "https://second.example/hook");
    let first_effects = journal.applied_effects();
    assert_eq!(first_effects.notify.len(), 1);
    journal.effects_finished(first_effects.owner);
    journal.cancelled();
    assert!(journal
        .settle(&settlement(&second, Ok(Decision::Applied)))
        .unwrap());
    let second_effects = journal.applied_effects();
    assert_eq!(second_effects.notify.len(), 1);
    assert_eq!(second_effects.backends[0].1, "backend-2");
    assert_eq!(
        second_effects.notify[0]
            .1
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap()
            .url,
        "https://second.example/hook"
    );
}

#[test]
fn non_applied_settlement_never_fabricates_effects_and_unknown_stays_retained() {
    for decision in [
        Ok(Decision::ConditionConflict),
        Err(wire::ConditionalFailure::Refused("refused")),
        Err(wire::ConditionalFailure::Indeterminate),
        Err(wire::ConditionalFailure::OpIdConflict),
    ] {
        let journal = Journal::default();
        journal.enter(TICKET, &input(&[])).unwrap();
        let original = notification(&journal, 1, "https://original.example/hook");
        journal.cancelled();
        let receipt = settlement(&original, decision.clone());
        assert!(journal.settle(&receipt).unwrap());
        let effects = journal.applied_effects();
        assert!(
            effects.notify.is_empty() && effects.backends.is_empty() && effects.deletes.is_empty()
        );
        journal.offer_ack(&receipt);
        assert_eq!(
            journal.ack_confirmed(None),
            matches!(
                decision,
                Ok(Decision::ConditionConflict) | Err(wire::ConditionalFailure::Refused(_))
            )
        );
        assert!(!journal.cancelled_without_receipt());
    }
}

#[test]
fn detached_applied_acknowledges_only_the_original_owed_receipt() {
    let deliveries = crate::push::Deliveries::default();
    let delivery = crate::push::Delivery {
        task_id: "t1".into(),
        caller: "aa".into(),
        url: "https://hook.example".into(),
        body: Vec::new(),
        terminal: false,
        auth: None,
        from_config: true,
        unresolved: None,
    };
    deliveries.owe(&delivery, crate::push::Attempted::Delivered);
    deliveries.owe(&delivery, crate::push::Attempted::Delivered);
    let owed = deliveries.peek_owed(TICKET, "aa", None).pop().unwrap();
    let journal = Journal::default();
    journal.enter(TICKET, &input(&[])).unwrap();
    let life = observed(&journal);
    let writes = [Write {
        kind: KIND_TASK_EVENT,
        key: KEY.into(),
        value: b"event".to_vec(),
    }];
    assert_eq!(
        journal.publish_with(
            5,
            &[],
            &[life],
            &writes,
            &Draft {
                owed: Some(owed.clone()),
                ..Draft::default()
            }
        ),
        Err(Halt::Pending)
    );
    let original = journal.0.with_all(|all| {
        let step = all.get_mut(&()).unwrap().steps.last_mut().unwrap();
        step.submitted = true;
        let Action::Publish { request, .. } = &step.action else {
            panic!("publish")
        };
        request.clone()
    });
    journal.cancelled();
    assert_eq!(journal.owed_decision(&owed), None);
    assert!(journal
        .settle(&settlement(&original, Ok(Decision::Applied)))
        .unwrap());
    let effects = journal.applied_effects();
    assert_eq!(effects.owed, vec![owed.clone()]);
    deliveries.acknowledge_owed(&effects.owed[0]);
    journal.effects_finished(effects.owner);
    let successor = deliveries.peek_owed(TICKET, "aa", None).pop().unwrap();
    assert_eq!(successor.outcome, owed.outcome);
    assert_ne!(successor, owed);
    assert!(journal.applied_effects().owed.is_empty());
    deliveries.acknowledge_owed(&owed);
    assert_eq!(deliveries.peek_owed(TICKET, "aa", None), vec![successor]);
}

#[test]
fn unsubmitted_successor_does_not_pin_an_acknowledged_original_commit() {
    let journal = Journal::default();
    journal.enter(TICKET, &input(&[])).unwrap();
    let original = notification(&journal, 1, "https://original.example/hook");
    let receipt = settlement(&original, Ok(Decision::Applied));
    let result = wire::encode_result(&original, &receipt.result).unwrap();
    journal.enter(TICKET, &input(&result)).unwrap();
    notification(&journal, 2, "https://unsubmitted.example/hook");
    journal.0.with_all(|all| {
        all.get_mut(&())
            .unwrap()
            .steps
            .last_mut()
            .unwrap()
            .submitted = false
    });
    journal.cancelled();
    assert!(journal.settle(&receipt).unwrap());
    let effects = journal.applied_effects();
    assert_eq!(effects.notify.len(), 1);
    journal.effects_finished(effects.owner);
    journal.offer_ack(&receipt);
    assert!(journal.ack_confirmed(None));
}

#[test]
fn canceled_observation_after_applied_settles_locally_without_waiting_for_a_commit_ack() {
    let journal = Journal::default();
    journal.enter(TICKET, &input(&[])).unwrap();
    let original = notification(&journal, 1, "https://original.example/hook");
    let result = wire::encode_result(
        &original,
        &wire::ConditionalResult {
            correlation: original.candidate.correlation,
            decision: Ok(Decision::Applied),
        },
    )
    .unwrap();
    journal.enter(TICKET, &input(&result)).unwrap();
    assert_eq!(journal.observe(2, KIND_TASK_EVENT, KEY), Err(Halt::Pending));
    journal.0.with_all(|all| {
        all.get_mut(&())
            .unwrap()
            .steps
            .last_mut()
            .unwrap()
            .submitted = true
    });
    journal.cancelled();
    let effects = journal.applied_effects();
    assert_eq!(effects.notify.len(), 1);
    journal.effects_finished(effects.owner);
    assert!(journal.cancelled_without_receipt());
}

#[test]
fn config_deletion_withdraws_retained_notification_in_either_settlement_order() {
    for delete_first in [true, false] {
        let deliveries = crate::push::Deliveries::default();
        let journal = Journal::default();
        journal.enter(TICKET, &input(&[])).unwrap();
        let original = notification(&journal, 1, "https://withdrawn.example/hook");
        deliveries.retain_publication(&journal);
        journal.cancelled();
        if delete_first {
            deliveries.forget_config(KEY);
        }
        assert!(journal
            .settle(&settlement(&original, Ok(Decision::Applied)))
            .unwrap());
        let effects = deliveries.apply_publication(&journal);
        assert_eq!(
            effects.notify.len(),
            1,
            "terminal token cleanup keeps its task row"
        );
        if delete_first {
            assert_eq!(effects.notify[0].1, Some(Ok(None)));
        } else {
            deliveries.forget_config(KEY);
        }
        assert!(
            deliveries.next_due(0).is_none(),
            "deleted authority never survives settlement"
        );
    }
}

#[test]
fn config_withdrawal_is_scoped_to_the_original_caller_and_task() {
    let deliveries = crate::push::Deliveries::default();
    let journal = Journal::default();
    journal.enter(TICKET, &input(&[])).unwrap();
    let original = notification(&journal, 1, "https://original.example/hook");
    deliveries.retain_publication(&journal);
    deliveries.forget_config("another/t1");
    journal.cancelled();
    assert!(journal
        .settle(&settlement(&original, Ok(Decision::Applied)))
        .unwrap());
    deliveries.apply_publication(&journal);
    assert_eq!(
        deliveries.next_due(0).unwrap().url,
        "https://original.example/hook"
    );
}

#[test]
fn detached_ack_waits_for_the_original_claimed_effect_batch_to_complete() {
    let journal = Journal::default();
    let wakes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let wake = Arc::new(crate::push::Wakeup::default());
    let observed_wakes = wakes.clone();
    wake.insert(
        (),
        Arc::new(move || {
            observed_wakes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }),
    );
    journal.owner_wake(Arc::downgrade(&wake));
    journal.enter(TICKET, &input(&[])).unwrap();
    let original = notification(&journal, 1, "https://original.example/hook");
    let result = wire::encode_result(
        &original,
        &wire::ConditionalResult {
            correlation: original.candidate.correlation,
            decision: Ok(Decision::Applied),
        },
    )
    .unwrap();
    journal.enter(TICKET, &input(&result)).unwrap();
    let old_crossing = journal.applied_effects();
    assert_eq!(old_crossing.notify.len(), 1);
    assert!(!journal.effects_complete());

    journal.cancelled();
    let receipt = settlement(&original, Ok(Decision::Applied));
    assert!(journal.settle(&receipt).unwrap());
    let detached = journal.applied_effects();
    assert!(detached.notify.is_empty() && detached.backends.is_empty());
    journal.effects_finished(detached.owner);
    assert!(
        !journal.effects_complete(),
        "another crossing cannot complete the original batch"
    );
    journal.offer_ack(&receipt);
    assert!(
        !journal.ack_confirmed(None),
        "in-flight effects retain receipt custody"
    );
    journal.effects_finished(old_crossing.owner);
    assert_eq!(
        wakes.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "completion wakes the existing driver"
    );
    assert!(journal.effects_complete());
    assert!(journal.ack_confirmed(None));
    assert!(journal.applied_effects().notify.is_empty());
}

#[test]
fn completing_an_earlier_batch_cannot_ack_a_newly_applied_candidate() {
    let journal = Journal::default();
    journal.enter(TICKET, &input(&[])).unwrap();
    let first = notification(&journal, 1, "https://first.example/hook");
    let result = wire::encode_result(
        &first,
        &wire::ConditionalResult {
            correlation: first.candidate.correlation,
            decision: Ok(Decision::Applied),
        },
    )
    .unwrap();
    journal.enter(TICKET, &input(&result)).unwrap();
    let second = notification(&journal, 2, "https://second.example/hook");
    let earlier = journal.applied_effects();
    assert_eq!(earlier.notify.len(), 1);
    journal.cancelled();
    let receipt = settlement(&second, Ok(Decision::Applied));
    assert!(journal.settle(&receipt).unwrap());
    assert!(
        journal.applied_effects().notify.is_empty(),
        "earlier batch still owns effects"
    );
    journal.effects_finished(earlier.owner);
    assert!(
        !journal.effects_complete(),
        "newly Applied obligations still need a batch"
    );
    journal.offer_ack(&receipt);
    assert!(!journal.ack_confirmed(None));
    let later = journal.applied_effects();
    assert_eq!(later.notify.len(), 1);
    journal.effects_finished(later.owner);
    assert!(journal.effects_complete());
    assert!(journal.ack_confirmed(None));
}

#[test]
fn a_late_retired_crossing_cannot_retain_an_already_acknowledged_journal() {
    let deliveries = crate::push::Deliveries::default();
    let journal = Journal::default();
    journal.enter(TICKET, &input(&[])).unwrap();
    let original = notification(&journal, 1, "https://original.example/hook");
    deliveries.retain_publication(&journal);
    journal.cancelled();
    let receipt = settlement(&original, Ok(Decision::Applied));
    assert!(journal.settle(&receipt).unwrap());
    let effects = journal.applied_effects();
    journal.effects_finished(effects.owner);
    journal.offer_ack(&receipt);
    assert!(journal.ack_confirmed(None));
    deliveries.release_publication(&journal);
    assert!(deliveries.publications().is_empty());
    deliveries.retain_publication(&journal);
    assert!(
        deliveries.publications().is_empty(),
        "late old callback cannot recreate receipt custody"
    );
    assert!(journal.enter(TICKET, &input(&[])).is_err());
    assert!(journal.completed());
}

#[test]
fn an_ordinary_completed_journal_can_retain_its_next_authenticated_epoch() {
    let deliveries = crate::push::Deliveries::default();
    let journal = Journal::default();
    journal.enter(TICKET, &input(&[])).unwrap();
    let original = notification(&journal, 1, "https://original.example/hook");
    let result = wire::encode_result(
        &original,
        &wire::ConditionalResult {
            correlation: original.candidate.correlation,
            decision: Ok(Decision::Applied),
        },
    )
    .unwrap();
    journal.enter(TICKET, &input(&result)).unwrap();
    let effects = journal.applied_effects();
    journal.effects_finished(effects.owner);
    journal.finished();
    deliveries.release_publication(&journal);
    journal
        .enter(
            TICKET,
            &wire::encode_capability(wire::Capability {
                epoch: 8,
                ..capability()
            }),
        )
        .unwrap();
    notification(&journal, 1, "https://next.example/hook");
    deliveries.retain_publication(&journal);
    assert_eq!(deliveries.publications().len(), 1);
}
