// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door's half of the task verbs: the restore claim, the records reach and the record kind
//! indices.

use super::*;

/// The instance's very first local verb runs its restore, and no local verb after it does, whatever
/// second it arrives in.
#[test]
fn only_the_first_local_verb_restores_and_none_sweeps() {
    let restored = Keyed::new();
    assert!(claim_restore(&restored, 10, TICKET), "the first restores");
    assert!(!claim_restore(&restored, 10, TICKET));
    assert!(
        !claim_restore(&restored, 11, TICKET),
        "the next second restores nothing"
    );
}

/// A record write names its kind by its index in the tail's record kinds.
#[test]
fn a_write_names_its_kind_by_the_tails_index() {
    use crate::records::{KIND_PUSH_CONFIG, KIND_TASK, KIND_TASK_EVENT};
    assert_eq!(
        [KIND_TASK, KIND_TASK_EVENT, KIND_PUSH_CONFIG].map(kind_index),
        [0, 1, 2]
    );
    assert_eq!(
        kind_index("pin"),
        u32::MAX,
        "a kind the tail does not state"
    );
}

use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables};
use busbar_contract::abi::sdk::conn::Host;

// Present but unarmed matches the original fixture: Via::issue requires Services before it
// invokes the assertion-specific closure. No callback supplies an invented success result.
static UNARMED_TASK_SERVICES: std::sync::LazyLock<busbar_contract::abi::host::service::HostSlots> =
    std::sync::LazyLock::new(|| busbar_contract::abi::host::service::HostSlots {
        size: std::mem::size_of::<busbar_contract::abi::host::service::HostSlots>() as u32,
        slots: busbar_contract::abi::host::service::SERVICES,
        ..busbar_contract::abi::sdk::test_support::zeroed()
    });
fn unarmed_task_services() -> HostTables {
    HostTables {
        size: std::mem::size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx { handle: 0 },
        wake: None,
        conns: std::ptr::null(),
        services: &*UNARMED_TASK_SERVICES,
        io: std::ptr::null(),
    }
}

const TICKET: Ticket = Ticket {
    slot: 3,
    generation: 7,
};

/// The size a long record needs: past the first read's room.
const LONG: u64 = RECORD_BYTES as u64 + 1;

/// A host that holds one long record: a buffer short of it is answered short at its size, one that
/// holds it is answered with it.
fn long_record(
    log: &mut Vec<(u32, usize)>,
    handle: CompletionHandle,
    buf: &[u8],
) -> Poll<Result<usize, ServiceError>> {
    log.push((handle.seq, buf.len()));
    if (buf.len() as u64) < LONG {
        Poll::Ready(Err(ServiceError::Short {
            bytes: LONG,
            items: 1,
        }))
    } else {
        Poll::Ready(Ok(buf.len()))
    }
}

/// A short answer is re-called ONCE, on the same handle, at the size it named.
#[test]
#[allow(unsafe_code)]
fn a_short_records_answer_is_re_called_once_on_its_handle_at_the_named_size() {
    let tables = unarmed_task_services();
    // SAFETY: this complete immutable table advertises the full static service prefix.
    // Every callback is None; no context or callback points at borrowed state.
    let host = unsafe { Host::from_raw(&tables) };
    // SAFETY: same readable static service prefix, with every callback None.
    let services = unsafe { Services::from_raw(&tables) };
    let grown = Keyed::new();
    let mut via = Via::new(&host, services, TICKET, 0, &grown);
    let mut log = Vec::new();
    let got = via.issue((RECORD_BYTES, 1), |_, h, buf, _| {
        long_record(&mut log, h, buf)
    });
    assert!(matches!(got, Ok(n) if n as u64 == LONG));
    assert_eq!(log, vec![(0, RECORD_BYTES), (0, LONG as usize)]);
    assert_eq!(via.issued(), 1, "one handle, issued twice");
}

/// A piece that answers PENDING runs again from the top: the handle a short answer already sized is
/// re-issued at that size, so the host never answers it short a second time (that is FAULT).
#[test]
#[allow(unsafe_code)]
fn a_piece_run_again_issues_a_short_handle_at_the_size_already_named() {
    let tables = unarmed_task_services();
    // SAFETY: this complete immutable table advertises the full static service prefix.
    // Every callback is None; no context or callback points at borrowed state.
    let host = unsafe { Host::from_raw(&tables) };
    // SAFETY: same readable static service prefix, with every callback None.
    let services = unsafe { Services::from_raw(&tables) };
    let grown = Keyed::new();
    let mut log = Vec::new();

    {
        let mut via = Via::new(&host, services, TICKET, 0, &grown);
        assert!(via
            .issue((RECORD_BYTES, 1), |_, h, buf, _| long_record(
                &mut log, h, buf
            ))
            .is_ok());
        let pends: Result<(), Halt> = via.issue((RECORD_BYTES, 1), |_, h, buf, _| {
            log.push((h.seq, buf.len()));
            Poll::Pending
        });
        assert!(matches!(pends, Err(Halt::Pending)));
    }
    log.clear();

    let mut via = Via::new(&host, services, TICKET, 0, &grown);
    assert!(via
        .issue((RECORD_BYTES, 1), |_, h, buf, _| long_record(
            &mut log, h, buf
        ))
        .is_ok());
    assert_eq!(log, vec![(0, LONG as usize)]);
}

/// A host that names a size and then answers short at it broke its own rule.
#[test]
#[allow(unsafe_code)]
fn a_second_short_answer_on_one_handle_is_a_broken_host() {
    let tables = unarmed_task_services();
    // SAFETY: this complete immutable table advertises the full static service prefix.
    // Every callback is None; no context or callback points at borrowed state.
    let host = unsafe { Host::from_raw(&tables) };
    // SAFETY: same readable static service prefix, with every callback None.
    let services = unsafe { Services::from_raw(&tables) };
    let grown = Keyed::new();
    let mut via = Via::new(&host, services, TICKET, 0, &grown);
    let got: Result<(), Halt> = via.issue((RECORD_BYTES, 1), |_, _, _, _| {
        Poll::Ready(Err(ServiceError::Short {
            bytes: LONG,
            items: 1,
        }))
    });
    assert!(matches!(got, Err(Halt::Failed(w)) if w == "Broken"));
}

/// No host services: every records call fails, and nothing is crossed.
#[test]
#[allow(unsafe_code)]
fn a_door_opened_with_no_services_reads_no_record() {
    let tables = HostTables {
        services: std::ptr::null(),
        ..unarmed_task_services()
    };
    // SAFETY: the complete immutable table explicitly advertises no services or connectors.
    // No context or callback points at borrowed state.
    let host = unsafe { Host::from_raw(&tables) };
    let grown = Keyed::new();
    let mut via = Via::new(&host, None, TICKET, 0, &grown);
    assert!(matches!(via.get("task", "k"), Err(Halt::Failed(w)) if w == "Unserved"));
    assert!(matches!(via.list("task", ""), Err(Halt::Failed(w)) if w == "Unserved"));
    assert!(matches!(via.claim("task", "k", 1), Err(Halt::Failed(w)) if w == "Unserved"));
}

/// The sizes book stays bounded without evicting any active ticket's replay state.
#[test]
#[allow(unsafe_code)]
fn the_sizes_book_is_bounded() {
    let tables = unarmed_task_services();
    // SAFETY: this complete immutable table advertises the full static service prefix.
    // Every callback is None; no context or callback points at borrowed state.
    let host = unsafe { Host::from_raw(&tables) };
    // SAFETY: same readable static service prefix, with every callback None.
    let services = unsafe { Services::from_raw(&tables) };
    let grown = Keyed::new();
    let via = Via::new(&host, services, TICKET, 0, &grown);
    for seq in 0..GROWN_MAX as u32 {
        via.grow(
            CompletionHandle {
                ticket: TICKET,
                seq,
                _reserved: 0,
            },
            1,
            1,
        )
        .unwrap();
    }
    assert_eq!(grown.len(), GROWN_MAX);
    assert!(matches!(
        via.grow(
            CompletionHandle {
                ticket: TICKET,
                seq: u32::MAX,
                _reserved: 0,
            },
            1,
            1,
        ),
        Err(Halt::Failed(_))
    ));
    assert_eq!(grown.len(), GROWN_MAX);
    assert!(grown.get(&grown_key(handle(TICKET, 0))).is_some());
}

#[path = "task_door_lifecycle_cases.rs"]
mod lifecycle_cases;

impl Via<'_> {
    fn claim(&mut self, kind: &str, key: &str, ttl_ms: u64) -> Result<bool, Halt> {
        self.issue((0, 0), |services, handle, _, _| {
            services.records_claim(handle, kind, key.as_bytes(), ttl_ms)
        })
    }
}

#[test]
fn oversized_host_scratch_and_unbounded_scans_are_refused() {
    assert!(check_record_room(MAX_RECORD_ROOM, MAX_RECORD_ITEMS).is_ok());
    assert!(matches!(
        check_record_room(u64::MAX, 1),
        Err(Halt::Failed(_))
    ));
    assert!(matches!(
        check_record_room(1, u64::MAX),
        Err(Halt::Failed(_))
    ));
    assert!(check_scan_room(MAX_SCAN_ROWS, MAX_SCAN_BYTES).is_ok());
    assert!(check_scan_room(MAX_SCAN_ROWS + 1, 0).is_err());
    assert!(check_scan_room(0, MAX_SCAN_BYTES + 1).is_err());
}

#[test]
fn local_answer_windows_share_one_wiping_allocation() {
    use crate::tests::raw_custody_probe::{assert_wiped, SECRET};
    assert_wiped(|| {
        let body = Remaining::new(SECRET);
        let pointer = body.bytes.as_slice().as_ptr();
        let mut tail = body.clone();
        for offset in 0..SECRET.len() {
            assert_eq!(tail.bytes.as_slice().as_ptr(), pointer);
            assert_eq!(tail.as_slice(), &SECRET[offset..]);
            tail = tail.advance(1);
        }
        assert!(tail.is_empty());
        assert_eq!(
            body.as_slice(),
            SECRET,
            "a retained SHORT replay is unchanged"
        );
        assert!(!format!("{body:?}").contains(std::str::from_utf8(SECRET).unwrap()));
    });
}

#[test]
fn mirrored_capability_is_only_for_the_tasks_holding_agent() {
    use crate::a2a::task::{Direction, Task, TaskState};
    let mut task = Task::submitted("task", "context", "caller", Direction::Inbound, 1).unwrap();
    task.agent_id = "agent-a".into();
    assert!(mirror_owns_task(&task, "agent-a"));
    assert!(!mirror_owns_task(&task, "agent-b"));
    task.state = TaskState::Completed;
    assert!(!mirror_owns_task(&task, "agent-a"));
}

#[test]
fn malformed_notification_config_is_not_treated_as_absent() {
    assert!(matches!(decode_notification_config(None), Ok(None)));
    assert!(decode_notification_config(Some(b"not-json-secret")).is_err());
    assert!(decode_notification_config(Some(b"null")).is_err());
}

#[test]
#[allow(unsafe_code)]
fn oversized_short_answer_is_refused_before_allocation_or_reissue() {
    let tables = unarmed_task_services();
    // SAFETY: the immutable complete table and its static callbacks outlive both wrappers.
    let host = unsafe { Host::from_raw(&tables) };
    // SAFETY: the same immutable complete table remains live through the operation.
    let services = unsafe { Services::from_raw(&tables) };
    let grown = Keyed::new();
    let mut via = Via::new(&host, services, TICKET, 0, &grown);
    let mut calls = 0;
    let answer: Result<(), Halt> = via.issue((RECORD_BYTES, 1), |_, _, _, _| {
        calls += 1;
        if calls == 1 {
            Poll::Ready(Err(ServiceError::Short {
                bytes: MAX_RECORD_ROOM + 1,
                items: 1,
            }))
        } else {
            Poll::Ready(Ok(()))
        }
    });
    assert!(matches!(answer, Err(Halt::Failed(_))));
    assert_eq!(calls, 1);
    assert_eq!(via.scratch.len(), RECORD_BYTES);
}

#[test]
#[allow(unsafe_code)]
fn quota_bootstrap_does_not_consume_task_effects_or_relax_mixed_publications() {
    use crate::conditional_publication::{Draft, Journal};
    use crate::records::{KIND_PUSH_CONFIG, KIND_TASK, KIND_TASK_QUOTA};
    use crate::tasks::{ChainLife, Predicate};
    use busbar_contract::abi::sdk::plane::conditional as wire;

    // Only a nonempty quota-only transaction with quota-only predicates and no chains is
    // administrative. Mixed writes/predicates, chains, and empty writes still require a task.
    for (write_kind, predicate_kind, chained, empty) in [
        (KIND_TASK_QUOTA, KIND_TASK_QUOTA, false, false),
        (KIND_PUSH_CONFIG, KIND_TASK_QUOTA, false, false),
        (KIND_TASK, KIND_TASK_QUOTA, false, false),
        (KIND_TASK_QUOTA, KIND_TASK, false, false),
        (KIND_TASK_QUOTA, KIND_TASK_QUOTA, true, false),
        (KIND_TASK_QUOTA, KIND_TASK_QUOTA, false, true),
    ] {
        let tables = unarmed_task_services();
        // SAFETY: the complete immutable service table lives through this synchronous test.
        let host = unsafe { Host::from_raw(&tables) };
        // SAFETY: same readable service prefix; callbacks remain intentionally unarmed.
        let services = unsafe { Services::from_raw(&tables) };
        let grown = Keyed::new();
        let journal = Journal::default();
        journal
            .enter(
                TICKET,
                &wire::encode_capability(wire::Capability {
                    ticket: TICKET,
                    epoch: 1,
                }),
            )
            .unwrap();
        let mut via = Via::new(&host, services, TICKET, 0, &grown).publishing(&journal);
        via.effects(Draft {
            notify: true,
            backend: Some("backend-task".into()),
            ..Default::default()
        });
        let predicates = [Predicate {
            kind: predicate_kind,
            key: "active/v1".into(),
            expected: None,
        }];
        let writes = if empty {
            Vec::new()
        } else {
            vec![
                Write {
                    kind: KIND_TASK_QUOTA,
                    key: "active/v1".into(),
                    value: b"{}".to_vec(),
                },
                // A task tombstone cannot satisfy the notification's required live row.
                Write {
                    kind: write_kind,
                    key: "other".into(),
                    value: Vec::new(),
                },
            ]
        };
        let chains = if chained {
            vec![ChainLife {
                kind: crate::records::KIND_TASK_EVENT,
                scope: "task".into(),
                expected: None,
            }]
        } else {
            Vec::new()
        };
        let result = via.publish(&predicates, &chains, &writes);
        if write_kind == KIND_TASK_QUOTA && predicate_kind == KIND_TASK_QUOTA && !chained && !empty
        {
            assert_eq!(
                result,
                Err(Halt::Pending),
                "quota publication must reach the conditional host"
            );
            assert!(journal.has_commit());
        } else {
            assert_eq!(
                result,
                Err(Halt::Failed("notification task unavailable".into()))
            );
            assert!(
                !journal.has_commit(),
                "no malformed task transaction was retained"
            );
        }
        assert!(
            via.effects.notify,
            "bootstrap must retain the subsequent task notification"
        );
        assert_eq!(via.effects.backend.as_deref(), Some("backend-task"));
    }
}
