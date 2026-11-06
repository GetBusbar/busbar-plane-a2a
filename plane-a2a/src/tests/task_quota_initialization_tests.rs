// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn initializing(book: &mut Book) {
    book.apply(&[Write {
        kind: KIND_TASK_QUOTA,
        key: GLOBAL.into(),
        value: br#"{"version":1,"epoch":1,"active":null}"#.to_vec(),
    }]);
}

#[test]
fn quota_populated_store_without_ready_gate_is_never_reconstructed() {
    for with_gate in [false, true] {
        for count in [1, crate::task_quota::MAX_ACTIVE + 1] {
            for terminal in [false, true] {
                let mut book = without_quota(count);
                if terminal {
                    for index in 0..count {
                        let mut held = row(&format!("existing-{index}"), 100);
                        held.principal = ALICE.into();
                        held.state = "completed".into();
                        book.hold(
                            ALICE,
                            &HeldTask {
                                row: held,
                                next_seq: 1,
                            },
                        );
                    }
                }
                if with_gate {
                    initializing(&mut book);
                }
                let before = book.clone();
                assert!(matches!(
                    open_configured(&mut book, &step(BOB, 200), row("new", 200), "planner", None),
                    Err(Halt::Failed(_))
                ));
                assert_eq!(book, before);
                assert!(transition(
                    &mut book,
                    &step(ALICE, 200),
                    "existing-0",
                    TaskState::Canceled,
                    &mut Vec::new()
                )
                .is_err());
                assert_eq!(book, before);
                assert!(write_config(
                    &mut book,
                    &step(ALICE, 200),
                    "existing-0",
                    None,
                    b"config".to_vec()
                )
                .is_err());
                assert_eq!(book, before);
            }
        }
    }
}

#[test]
fn quota_empty_initialization_refuses_orphaned_task_state_or_principal_counts() {
    for with_gate in [false, true] {
        for kind in [KIND_TASK_EVENT, KIND_PUSH_CONFIG, KIND_TASK_QUOTA] {
            let mut book = without_quota(0);
            if with_gate {
                initializing(&mut book);
            }
            let (key, value) = if kind == KIND_TASK_EVENT {
                let held = HeldTask {
                    row: row("orphan", 100),
                    next_seq: 1,
                };
                (
                    task_key(ALICE, "orphan"),
                    suffix(&seal_event(&held, &held.row, EV_SUBMITTED, "orphan", 100)),
                )
            } else {
                (
                    format!("1/{ALICE}"),
                    br#"{"version":1,"epoch":1,"active":1}"#.to_vec(),
                )
            };
            book.apply(&[Write { kind, key, value }]);
            let before = book.clone();
            assert!(
                open_configured(&mut book, &step(BOB, 200), row("new", 200), "planner", None)
                    .is_err()
            );
            assert_eq!(book, before);
        }
    }
}

struct ActivateDuringListing {
    book: Book,
    armed: bool,
}

impl Records for ActivateDuringListing {
    fn quota_bootstrap_allowed(&mut self) -> Result<bool, Halt> {
        Ok(true)
    }
    fn get(&mut self, kind: &str, key: &str) -> Result<Option<Vec<u8>>, Halt> {
        self.book.get(kind, key)
    }
    fn list(&mut self, kind: &str, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, Halt> {
        // The outer call already read a missing/initializing gate and empty quota listing.
        // Another caller completes initialization and admits a task before its task scan.
        if self.armed && kind == KIND_TASK {
            self.armed = false;
            open_configured(
                &mut self.book,
                &step(ALICE, 200),
                row("competing", 200),
                "planner",
                None,
            )
            .unwrap();
        }
        self.book.list(kind, prefix)
    }
    fn observe_chain_life(&mut self, kind: &str, scope: &str) -> Result<Option<Vec<u8>>, Halt> {
        self.book.observe_chain_life(kind, scope)
    }
    fn publish(
        &mut self,
        predicates: &[Predicate],
        chains: &[ChainLife],
        writes: &[Write],
    ) -> Result<bool, Halt> {
        self.book.publish(predicates, chains, writes)
    }
}

#[test]
fn quota_concurrent_activation_during_empty_scan_retries_changed_gate() {
    for with_gate in [false, true] {
        let mut book = without_quota(0);
        if with_gate {
            initializing(&mut book);
        }
        let mut records = ActivateDuringListing { book, armed: true };
        assert!(open_configured(
            &mut records,
            &step(BOB, 200),
            row("new", 200),
            "planner",
            None
        )
        .is_ok());
        assert!(!records.armed);
        assert_eq!(total(&records.book), 2);
        assert_eq!(principal_count(&records.book, ALICE), 1);
        assert_eq!(principal_count(&records.book, BOB), 1);
        assert!(records
            .book
            .value(KIND_TASK, &task_key(ALICE, "competing"))
            .is_some());
        assert!(records
            .book
            .value(KIND_TASK, &task_key(BOB, "new"))
            .is_some());
    }
}

#[test]
fn quota_fresh_initialization_replays_lost_barrier_and_activation_receipts() {
    let host = Rc::new(RefCell::new(without_quota(0)));
    let mut call = Call::new(&host);
    for _ in 0..2 {
        call.replay();
        assert_eq!(
            open_configured(
                &mut call,
                &step(ALICE, 200),
                row("new", 200),
                "planner",
                None
            ),
            Err(Halt::Pending)
        );
        let exact = call.offered().clone();
        assert!(call.commit(false));
        assert!(host
            .borrow()
            .value(KIND_TASK, &task_key(ALICE, "new"))
            .is_none());
        call.replay();
        assert_eq!(
            open_configured(
                &mut call,
                &step(ALICE, 200),
                row("new", 200),
                "planner",
                None
            ),
            Err(Halt::Pending)
        );
        assert_eq!(call.offered(), &exact);
        assert!(call.commit(true));
    }
    assert!(finish_open(&mut call, ALICE, "new").is_ok());
    assert_eq!(total(&host.borrow()), 1);
    assert_eq!(principal_count(&host.borrow(), ALICE), 1);
    assert_eq!(
        host.borrow_mut().list(KIND_TASK_EVENT, "").unwrap().len(),
        2
    );
}
