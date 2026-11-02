// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::records::KIND_PUSH_CONFIG;
use crate::tests::raw_custody_probe::{Probe, SECRET};

fn capability() -> wire::Capability {
    wire::Capability {
        ticket: Ticket {
            slot: 22,
            generation: 3,
        },
        epoch: 7,
    }
}

fn pending() -> Journal {
    let journal = Journal::default();
    let capability = capability();
    journal
        .enter(capability.ticket, &wire::encode_capability(capability))
        .unwrap();
    let predicates = [Predicate {
        kind: KIND_PUSH_CONFIG,
        key: "aa/task".into(),
        expected: Some(SECRET.to_vec()),
    }];
    let writes = [Write {
        kind: KIND_PUSH_CONFIG,
        key: "aa/task".into(),
        value: SECRET.to_vec(),
    }];
    assert_eq!(
        journal.publish(1, &predicates, &[], &writes),
        Err(Halt::Pending)
    );
    journal
}

#[test]
fn malformed_candidate_retires_partial_predicate_credentials() {
    let predicates = [
        Predicate {
            kind: KIND_PUSH_CONFIG,
            key: "aa/task".into(),
            expected: Some(SECRET.to_vec()),
        },
        Predicate {
            kind: "undeclared",
            key: "aa/task".into(),
            expected: None,
        },
    ];
    let probe = Probe::start();
    assert!(candidate(capability(), 1, &predicates, &[], &[]).is_err());
    assert_eq!(
        probe.retirements(),
        1,
        "the successfully cloned prior predicate has its own custody"
    );
    probe.checkpoint();
}

#[test]
fn clearing_definitive_journal_steps_retires_every_retained_raw_owner() {
    for decision in [
        Ok(Decision::Applied),
        Ok(Decision::ConditionConflict),
        Err(wire::ConditionalFailure::Refused("refused")),
    ] {
        let journal = pending();
        journal.0.with_all(|all| {
            let Action::Publish {
                answer,
                metadata_taken,
                ..
            } = &mut all.get_mut(&()).unwrap().steps[0].action
            else {
                unreachable!()
            };
            *answer = Some(decision);
            *metadata_taken = true;
        });
        let probe = Probe::start();
        journal.finished();
        assert!(journal.completed());
        assert_eq!(
            probe.retirements(),
            3,
            "predicate, candidate mutation and retained write are independent owners"
        );
        probe.checkpoint();
    }
}

#[test]
fn cancel_keeps_a_submitted_candidate_until_its_original_journal_is_released() {
    let journal = pending();
    journal
        .0
        .with_all(|all| all.get_mut(&()).unwrap().steps[0].submitted = true);
    let probe = Probe::start();
    journal.cancelled();
    assert_eq!(
        probe.retirements(),
        0,
        "cancellation cannot erase an unknown submitted candidate"
    );
    journal.0.with(&(), |state| {
        let Action::Publish { request, writes, .. } = &state.unwrap().steps[0].action else { unreachable!() };
        assert!(matches!(&request.candidate.predicates[0].expected, Expected::Bytes(value) if value == SECRET));
        assert_eq!(writes[0].value, SECRET);
    });
    drop(journal);
    assert_eq!(probe.retirements(), 3);
    probe.checkpoint();
}

#[test]
fn an_unsubmitted_cancel_or_unwind_retires_the_original_journal() {
    let journal = pending();
    let probe = Probe::start();
    journal.cancelled();
    assert_eq!(probe.retirements(), 3);
    probe.checkpoint();
    drop(probe);
    let journal = pending();
    let probe = Probe::start();
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _journal = journal;
        panic!("injected callback unwind");
    }));
    assert!(unwind.is_err());
    assert_eq!(probe.retirements(), 3);
    probe.checkpoint();
}

#[test]
fn cloning_a_pending_journal_keeps_one_shared_custodian_until_the_last_clone_releases() {
    let journal = pending();
    let replay = journal.clone();
    let probe = Probe::start();
    drop(journal);
    assert_eq!(probe.retirements(), 0);
    drop(replay);
    assert_eq!(probe.retirements(), 3);
    probe.checkpoint();
}
