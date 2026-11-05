// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::records::KIND_TASK_QUOTA;

const GLOBAL: &str = "active/v1";

fn total(book: &Book) -> u64 {
    let value: serde_json::Value =
        serde_json::from_slice(book.value(KIND_TASK_QUOTA, GLOBAL).unwrap()).unwrap();
    value["active"].as_u64().unwrap()
}

fn principal_count(book: &Book, caller: &str) -> u64 {
    book.value(KIND_TASK_QUOTA, &format!("1/{caller}"))
        .map(|bytes| {
            serde_json::from_slice::<serde_json::Value>(bytes).unwrap()["active"]
                .as_u64()
                .unwrap()
        })
        .unwrap_or(0)
}

fn legacy(count: u64) -> Book {
    let mut book = Book::default();
    book.apply(&[Write {
        kind: KIND_TASK_QUOTA,
        key: GLOBAL.into(),
        value: Vec::new(),
    }]);
    for index in 0..count {
        let mut held = row(&format!("legacy-{index}"), 100);
        held.principal = ALICE.into();
        book.hold(
            ALICE,
            &HeldTask {
                row: held,
                next_seq: 1,
            },
        );
    }
    book
}

fn initialized(count: u64) -> Book {
    let mut book = legacy(count);
    book.apply(&[
        Write {
            kind: KIND_TASK_QUOTA,
            key: GLOBAL.into(),
            value: format!(r#"{{"version":1,"epoch":1,"active":{count}}}"#).into_bytes(),
        },
        Write {
            kind: KIND_TASK_QUOTA,
            key: format!("1/{ALICE}"),
            value: format!(r#"{{"version":1,"epoch":1,"active":{count}}}"#).into_bytes(),
        },
    ]);
    book
}

fn finish_open(call: &mut Call, caller: &str, id: &str) -> Result<TaskRow, Halt> {
    for _ in 0..32 {
        call.replay();
        match open_configured(call, &step(caller, 200), row(id, 200), "planner", None) {
            Err(Halt::Pending) => {
                call.commit(true);
            }
            result => return result,
        }
    }
    panic!("bounded quota bootstrap failed to finish");
}

#[test]
fn quota_two_principals_cannot_both_take_the_last_global_slot() {
    let host = Rc::new(RefCell::new(initialized(crate::task_quota::MAX_ACTIVE - 1)));
    let mut alice = Call::new(&host);
    let mut bob = Call::new(&host);
    for (call, caller, id) in [(&mut alice, ALICE, "alice-new"), (&mut bob, BOB, "bob-new")] {
        assert_eq!(
            open_configured(call, &step(caller, 200), row(id, 200), "planner", None),
            Err(Halt::Pending)
        );
    }
    assert!(alice.commit(true));
    assert!(!bob.commit(true));
    assert!(finish_open(&mut alice, ALICE, "alice-new").is_ok());
    assert!(
        matches!(finish_open(&mut bob, BOB, "bob-new"), Err(Halt::Failed(message)) if message.contains("capacity"))
    );
    let book = host.borrow();
    assert_eq!(total(&book), crate::task_quota::MAX_ACTIVE);
    assert_eq!(principal_count(&book, ALICE), crate::task_quota::MAX_ACTIVE);
    assert_eq!(principal_count(&book, BOB), 0);
    assert!(book.value(KIND_TASK, &task_key(BOB, "bob-new")).is_none());
    assert!(book
        .value(KIND_PUSH_CONFIG, &task_key(BOB, "bob-new"))
        .is_none());
    assert!(book
        .value(KIND_TASK_EVENT, &event_key(BOB, "bob-new", 1))
        .is_none());
}

#[test]
fn quota_reads_straddling_a_same_principal_admission_retry_the_snapshot() {
    let host = Rc::new(RefCell::new(initialized(1)));
    let mut call = Call::new(&host);
    call.before_get = Some((KIND_TASK_QUOTA.into(), format!("1/{ALICE}"), |book| {
        open_configured(
            book,
            &step(ALICE, 200),
            row("competing", 200),
            "planner",
            None,
        )
        .unwrap();
    }));
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
    assert_eq!(total(&host.borrow()), 2);
    assert!(call.commit(true));
    assert!(finish_open(&mut call, ALICE, "new").is_ok());
    assert_eq!(total(&host.borrow()), 3);
    assert_eq!(principal_count(&host.borrow(), ALICE), 3);
}

#[test]
fn quota_last_task_terminal_between_reads_replans_instead_of_reporting_corruption() {
    let host = Rc::new(RefCell::new(initialized(1)));
    let mut call = Call::new(&host);
    call.before_get = Some((KIND_TASK_QUOTA.into(), format!("1/{ALICE}"), |book| {
        transition(
            book,
            &step(ALICE, 200),
            "legacy-0",
            TaskState::Completed,
            &mut Vec::new(),
        )
        .unwrap();
    }));
    let mut plan = |held: &TaskRow| {
        if held.state == "completed" {
            Ok(None)
        } else {
            plan_transition(TaskState::Completed, 200)(held).map(Some)
        }
    };
    assert_eq!(
        change(
            &mut call,
            &step(ALICE, 200),
            "legacy-0",
            &mut plan,
            &mut Vec::new()
        ),
        Ok(None)
    );
    assert_eq!(total(&host.borrow()), 0);
    assert_eq!(principal_count(&host.borrow(), ALICE), 0);
}

#[test]
fn quota_lost_genesis_receipt_replays_without_double_charge() {
    let host = Rc::new(RefCell::new(Book::default()));
    let mut call = Call::new(&host);
    assert_eq!(
        open_configured(
            &mut call,
            &step(ALICE, 200),
            row("new", 200),
            "planner",
            Some(b"config".to_vec())
        ),
        Err(Halt::Pending)
    );
    let exact = call.offered().clone();
    assert!(call.commit(false));
    assert_eq!(total(&host.borrow()), 1);
    call.replay();
    assert_eq!(
        open_configured(
            &mut call,
            &step(ALICE, 200),
            row("new", 200),
            "planner",
            Some(b"config".to_vec())
        ),
        Err(Halt::Pending)
    );
    assert_eq!(call.offered(), &exact);
    assert!(call.commit(true));
    call.replay();
    assert!(open_configured(
        &mut call,
        &step(ALICE, 200),
        row("new", 200),
        "planner",
        Some(b"config".to_vec())
    )
    .is_ok());
    assert_eq!(total(&host.borrow()), 1);
    assert_eq!(principal_count(&host.borrow(), ALICE), 1);
    assert_eq!(
        host.borrow_mut().list(KIND_TASK_EVENT, "").unwrap().len(),
        2
    );
}

#[test]
fn quota_terminal_and_genesis_race_preserves_both_counts_in_either_order() {
    for terminal_first in [true, false] {
        let host = Rc::new(RefCell::new(initialized(crate::task_quota::MAX_ACTIVE - 1)));
        let mut terminal = Call::new(&host);
        let mut genesis = Call::new(&host);
        assert_eq!(
            transition(
                &mut terminal,
                &step(ALICE, 200),
                "legacy-0",
                TaskState::Completed,
                &mut Vec::new()
            ),
            Err(Halt::Pending)
        );
        assert_eq!(
            open_configured(
                &mut genesis,
                &step(BOB, 200),
                row("new", 200),
                "planner",
                None
            ),
            Err(Halt::Pending)
        );
        if terminal_first {
            assert!(terminal.commit(true));
            assert!(!genesis.commit(true));
        } else {
            assert!(genesis.commit(true));
            assert!(!terminal.commit(true));
        }
        assert!(finish_open(&mut genesis, BOB, "new").is_ok());
        for _ in 0..4 {
            terminal.replay();
            match transition(
                &mut terminal,
                &step(ALICE, 200),
                "legacy-0",
                TaskState::Completed,
                &mut Vec::new(),
            ) {
                Err(Halt::Pending) => {
                    terminal.commit(true);
                }
                result => {
                    assert!(result.is_ok());
                    break;
                }
            }
        }
        assert_eq!(total(&host.borrow()), crate::task_quota::MAX_ACTIVE - 1);
        assert_eq!(
            principal_count(&host.borrow(), ALICE),
            crate::task_quota::MAX_ACTIVE - 2
        );
        assert_eq!(principal_count(&host.borrow(), BOB), 1);
        assert_eq!(
            get(&mut *host.borrow_mut(), ALICE, "legacy-0", 200)
                .unwrap()
                .unwrap()
                .row
                .state,
            "completed"
        );
    }
}

#[test]
fn quota_bootstrap_restarts_and_stale_initializer_cannot_overwrite_ready_counts() {
    let host = Rc::new(RefCell::new(legacy(2)));
    let mut abandoned = Call::new(&host);
    assert_eq!(
        open_configured(
            &mut abandoned,
            &step(BOB, 200),
            row("new", 200),
            "planner",
            None
        ),
        Err(Halt::Pending)
    );
    assert!(abandoned.commit(true)); // durable initializing barrier
    abandoned.replay();
    assert_eq!(
        open_configured(
            &mut abandoned,
            &step(BOB, 200),
            row("new", 200),
            "planner",
            None
        ),
        Err(Halt::Pending)
    );
    let stale = abandoned.offered().clone(); // principal reconstruction, still guarded by initializing
    assert!(abandoned.commit(true));
    drop(abandoned);
    let mut restarted = Call::new(&host);
    assert!(finish_open(&mut restarted, BOB, "new").is_ok());
    assert_eq!(total(&host.borrow()), 3);
    assert_eq!(principal_count(&host.borrow(), ALICE), 2);
    assert_eq!(principal_count(&host.borrow(), BOB), 1);
    let before = host.borrow().clone();
    assert!(!host
        .borrow_mut()
        .publish(&stale.predicates, &stale.chains, &stale.writes)
        .unwrap());
    assert_eq!(*host.borrow(), before);
}

#[test]
fn quota_legacy_over_limit_retains_active_tasks_and_allows_terminal_release() {
    let mut book = legacy(crate::task_quota::MAX_ACTIVE + 1);
    assert!(
        matches!(open_configured(&mut book, &step(BOB, 200), row("new", 200), "planner", None), Err(Halt::Failed(message)) if message.contains("capacity"))
    );
    assert_eq!(total(&book), crate::task_quota::MAX_ACTIVE + 1);
    assert_eq!(
        book.list(KIND_TASK, "").unwrap().len() as u64,
        crate::task_quota::MAX_ACTIVE + 1
    );
    assert!(transition(
        &mut book,
        &step(ALICE, 200),
        "legacy-0",
        TaskState::Completed,
        &mut Vec::new()
    )
    .is_ok());
    assert_eq!(total(&book), crate::task_quota::MAX_ACTIVE);
    assert!(book
        .value(KIND_TASK, &task_key(ALICE, "legacy-0"))
        .is_some());
}

struct Unattested(Book);

impl Records for Unattested {
    fn get(&mut self, kind: &str, key: &str) -> Result<Option<Vec<u8>>, Halt> {
        self.0.get(kind, key)
    }
    fn list(&mut self, kind: &str, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, Halt> {
        self.0.list(kind, prefix)
    }
    fn observe_chain_life(&mut self, kind: &str, scope: &str) -> Result<Option<Vec<u8>>, Halt> {
        self.0.observe_chain_life(kind, scope)
    }
    fn publish(
        &mut self,
        predicates: &[Predicate],
        chains: &[ChainLife],
        writes: &[Write],
    ) -> Result<bool, Halt> {
        self.0.publish(predicates, chains, writes)
    }
}

#[test]
fn quota_bootstrap_without_host_quiescence_proof_fails_closed() {
    for initializing in [false, true] {
        let mut book = legacy(1);
        if initializing {
            book.apply(&[Write {
                kind: KIND_TASK_QUOTA,
                key: GLOBAL.into(),
                value: br#"{"version":1,"epoch":1,"active":null}"#.to_vec(),
            }]);
        }
        let before = book.clone();
        let mut records = Unattested(book);
        assert!(matches!(
            open_configured(
                &mut records,
                &step(BOB, 200),
                row("new", 200),
                "planner",
                None
            ),
            Err(Halt::Failed(_))
        ));
        assert_eq!(records.0, before);
    }
}

#[test]
fn quota_initializing_gate_also_blocks_task_owned_config_without_host_proof() {
    let mut book = legacy(1);
    book.apply(&[Write {
        kind: KIND_TASK_QUOTA,
        key: GLOBAL.into(),
        value: br#"{"version":1,"epoch":1,"active":null}"#.to_vec(),
    }]);
    let before = book.clone();
    let mut records = Unattested(book);
    assert!(write_config(
        &mut records,
        &step(ALICE, 200),
        "legacy-0",
        None,
        b"private config".to_vec(),
    )
    .is_err());
    assert_eq!(records.0, before);
}

struct IncompleteListing(Book);

impl Records for IncompleteListing {
    fn quota_bootstrap_allowed(&mut self) -> Result<bool, Halt> {
        Ok(true)
    }
    fn get(&mut self, kind: &str, key: &str) -> Result<Option<Vec<u8>>, Halt> {
        self.0.get(kind, key)
    }
    fn list(&mut self, kind: &str, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, Halt> {
        if kind == KIND_TASK {
            return Err(Halt::Failed(
                "record listing exceeds the bounded scan capacity".into(),
            ));
        }
        self.0.list(kind, prefix)
    }
    fn observe_chain_life(&mut self, kind: &str, scope: &str) -> Result<Option<Vec<u8>>, Halt> {
        self.0.observe_chain_life(kind, scope)
    }
    fn publish(
        &mut self,
        predicates: &[Predicate],
        chains: &[ChainLife],
        writes: &[Write],
    ) -> Result<bool, Halt> {
        self.0.publish(predicates, chains, writes)
    }
}

#[test]
fn quota_failed_bounded_listing_never_activates_partial_accounting() {
    let mut records = IncompleteListing(legacy(1));
    assert!(open_configured(
        &mut records,
        &step(BOB, 200),
        row("new", 200),
        "planner",
        None
    )
    .is_err());
    let gate: serde_json::Value =
        serde_json::from_slice(records.0.value(KIND_TASK_QUOTA, GLOBAL).unwrap()).unwrap();
    assert!(gate["active"].is_null());
    assert!(records.0.value(KIND_TASK, &task_key(BOB, "new")).is_none());
    assert!(records
        .0
        .value(KIND_TASK_QUOTA, &format!("1/{ALICE}"))
        .is_none());
}

#[test]
fn quota_initialized_store_needs_no_bootstrap_capability_after_restart() {
    let mut records = Unattested(Book::default());
    assert!(open_configured(
        &mut records,
        &step(ALICE, 200),
        row("new", 200),
        "planner",
        None
    )
    .is_ok());
    assert_eq!(total(&records.0), 1);
    let mut restarted = Unattested(records.0.clone());
    assert_eq!(restore(&mut restarted).unwrap().active, 1);
    assert!(transition(
        &mut restarted,
        &step(ALICE, 201),
        "new",
        TaskState::Completed,
        &mut Vec::new()
    )
    .is_ok());
    assert_eq!(total(&restarted.0), 0);
    assert_eq!(principal_count(&restarted.0, ALICE), 0);
    assert!(restarted
        .0
        .value(KIND_TASK_QUOTA, &format!("1/{ALICE}"))
        .is_none());
}

#[test]
fn quota_corrupt_metadata_or_task_identity_never_resets_capacity() {
    for (kind, key, bytes) in [
        (
            KIND_TASK_QUOTA,
            GLOBAL.to_string(),
            br#"{"version":2,"epoch":1,"active":0}"#.to_vec(),
        ),
        (
            KIND_TASK_QUOTA,
            format!("1/{ALICE}"),
            br#"{"version":1,"epoch":1,"active":99}"#.to_vec(),
        ),
    ] {
        let mut book = Book::default();
        book.apply(&[Write {
            kind,
            key,
            value: bytes,
        }]);
        let before = book.clone();
        assert!(open_configured(
            &mut book,
            &step(ALICE, 200),
            row("new", 200),
            "planner",
            None
        )
        .is_err());
        assert_eq!(book, before);
    }
    let mut book = legacy(1);
    let mut mismatch = row("mismatch", 100);
    mismatch.principal = BOB.into();
    book.hold(
        ALICE,
        &HeldTask {
            row: mismatch,
            next_seq: 1,
        },
    );
    assert!(open_configured(&mut book, &step(BOB, 200), row("new", 200), "planner", None).is_err());
    assert!(book.value(KIND_TASK, &task_key(BOB, "new")).is_none());
    let gate: serde_json::Value =
        serde_json::from_slice(book.value(KIND_TASK_QUOTA, GLOBAL).unwrap()).unwrap();
    assert!(gate["active"].is_null());
}
