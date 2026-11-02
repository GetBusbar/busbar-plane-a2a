// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::records::KIND_PUSH_CONFIG;

const TICKET: Ticket = Ticket {
    slot: 27,
    generation: 4,
};

fn capability() -> wire::Capability {
    wire::Capability {
        ticket: TICKET,
        epoch: 9,
    }
}

fn input(receipt: &[u8]) -> Vec<u8> {
    let mut bytes = wire::encode_capability(capability());
    bytes.extend_from_slice(receipt);
    bytes
}

fn submitted() -> (Journal, wire::Request) {
    let journal = Journal::default();
    journal.enter(TICKET, &input(&[])).unwrap();
    assert_eq!(
        journal.publish(
            3,
            &[],
            &[],
            &[Write {
                kind: KIND_PUSH_CONFIG,
                key: "caller/task".into(),
                value: b"config".to_vec(),
            }]
        ),
        Err(Halt::Pending)
    );
    let request = journal.0.with_all(|all| {
        let step = &mut all.get_mut(&()).unwrap().steps[0];
        step.submitted = true;
        let Action::Publish { request, .. } = &step.action else {
            unreachable!()
        };
        request.clone()
    });
    (journal, request)
}

fn result(
    request: &wire::Request,
    decision: Result<Decision, wire::ConditionalFailure>,
) -> Vec<u8> {
    wire::encode_result(
        request,
        &wire::ConditionalResult {
            correlation: request.candidate.correlation,
            decision,
        },
    )
    .unwrap()
}

#[test]
fn only_the_exact_definitive_commit_refusal_selects_the_write_error() {
    let (journal, request) = submitted();
    assert!(!journal.response_only());
    assert!(!journal.refused_commit());
    let receipt = result(
        &request,
        Err(wire::ConditionalFailure::Refused("store refused")),
    );
    journal.enter(TICKET, &input(&receipt)).unwrap();
    assert!(journal.response_only());
    assert!(journal.refused_commit());
    assert!(journal.committed_writes().is_empty());
    assert_eq!(
        journal.publish(
            3,
            &[],
            &[],
            &[Write {
                kind: KIND_PUSH_CONFIG,
                key: "caller/task".into(),
                value: b"config".to_vec(),
            }]
        ),
        Err(failed())
    );
    journal.finished();
    assert!(journal.completed());
    assert!(
        journal.response_only(),
        "a partial reply retains its restriction"
    );
    assert!(journal.refused_commit());
}

#[test]
fn pending_conflict_and_unknown_results_do_not_become_definitive_refusals() {
    for decision in [
        Ok(Decision::ConditionConflict),
        Err(wire::ConditionalFailure::Indeterminate),
        Err(wire::ConditionalFailure::OpIdConflict),
    ] {
        let (journal, request) = submitted();
        let unknown = decision.is_err();
        let receipt = result(&request, decision);
        assert_eq!(journal.enter(TICKET, &input(&receipt)).is_err(), unknown);
        assert!(!journal.response_only());
        assert!(!journal.refused_commit());
        assert!(journal.committed_writes().is_empty());
    }
}

#[test]
fn successful_observation_and_applied_commit_keep_their_normal_authority() {
    let (journal, request) = submitted();
    journal
        .enter(TICKET, &input(&result(&request, Ok(Decision::Applied))))
        .unwrap();
    assert!(!journal.response_only());
    assert!(!journal.refused_commit());
    assert_eq!(journal.committed_writes().len(), 1);

    let observed = observation(Ok(Expected::Absent));
    assert!(!observed.response_only());
    assert!(!observed.refused_commit());
}

fn observation(answer: Result<Expected, wire::ConditionalFailure>) -> Journal {
    let journal = Journal::default();
    journal.enter(TICKET, &input(&[])).unwrap();
    assert_eq!(
        journal.observe(1, KIND_PUSH_CONFIG, "caller/task"),
        Err(Halt::Pending)
    );
    let request = journal.0.with_all(|all| {
        let step = &mut all.get_mut(&()).unwrap().steps[0];
        step.submitted = true;
        let Action::Observe { request, .. } = &step.action else {
            unreachable!()
        };
        request.clone()
    });
    let receipt = wire::encode_observed(
        &request,
        &wire::ObservationResult {
            correlation: request.correlation,
            result: answer,
        },
    )
    .unwrap();
    journal.enter(TICKET, &input(&receipt)).unwrap();
    journal
}

#[test]
fn a_refused_observation_cannot_impersonate_a_refused_write() {
    let journal = observation(Err(wire::ConditionalFailure::Refused("read refused")));
    assert!(journal.response_only());
    assert!(!journal.refused_commit());
    assert!(journal.committed_writes().is_empty());
}

#[test]
fn a_new_observation_cannot_wash_a_refused_commit_or_start_another_publication() {
    let (journal, request) = submitted();
    journal
        .enter(
            TICKET,
            &input(&result(
                &request,
                Err(wire::ConditionalFailure::Refused("refused")),
            )),
        )
        .unwrap();
    assert!(matches!(
        journal.observe(4, KIND_PUSH_CONFIG, "caller/task"),
        Err(Halt::Failed(_))
    ));
    assert!(matches!(
        journal.publish(5, &[], &[], &[]),
        Err(Halt::Failed(_))
    ));
    assert!(journal.response_only());
    assert!(journal.refused_commit());
}

#[test]
fn another_epoch_cannot_supply_the_refusal_proof() {
    let (journal, mut request) = submitted();
    request.capability.epoch += 1;
    let receipt = result(&request, Err(wire::ConditionalFailure::Refused("refused")));
    assert!(journal.enter(TICKET, &input(&receipt)).is_err());
    assert!(!journal.response_only());
    assert!(!journal.refused_commit());
}

#[test]
fn a_later_refusal_does_not_discard_already_applied_metadata_obligations() {
    let (journal, request) = submitted();
    journal
        .enter(TICKET, &input(&result(&request, Ok(Decision::Applied))))
        .unwrap();
    assert_eq!(
        journal.publish(
            4,
            &[],
            &[],
            &[Write {
                kind: KIND_PUSH_CONFIG,
                key: "caller/other".into(),
                value: b"refused config".to_vec(),
            }]
        ),
        Err(Halt::Pending)
    );
    let second = journal.0.with_all(|all| {
        let step = &mut all.get_mut(&()).unwrap().steps[1];
        step.submitted = true;
        let Action::Publish { request, .. } = &step.action else {
            unreachable!()
        };
        request.clone()
    });
    journal
        .enter(
            TICKET,
            &input(&result(
                &second,
                Err(wire::ConditionalFailure::Refused("refused")),
            )),
        )
        .unwrap();
    journal.finished();
    assert!(
        !journal.completed(),
        "the first Applied result still owns its metadata work"
    );
    let writes = journal.committed_writes();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].key, "caller/task");
    assert_eq!(writes[0].value, b"config");
    journal.finished();
    assert!(journal.completed());
    assert!(journal.response_only());
}
