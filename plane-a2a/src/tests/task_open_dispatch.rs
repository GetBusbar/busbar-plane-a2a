// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[derive(Clone, Copy)]
enum Refusal {
    Taken,
    Store,
}

struct RefusesDispatch {
    book: Book,
    refusal: Refusal,
}

impl Records for RefusesDispatch {
    fn get(&mut self, kind: &str, key: &str) -> Result<Option<Vec<u8>>, Halt> {
        self.book.get(kind, key)
    }
    fn list(&mut self, kind: &str, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, Halt> {
        self.book.list(kind, prefix)
    }
    fn claim(&mut self, kind: &str, key: &str, ttl_ms: u64) -> Result<bool, Halt> {
        if kind == KIND_TASK_EVENT && key == event_key(ALICE, "fresh", 2) {
            match self.refusal {
                Refusal::Taken => Ok(false),
                Refusal::Store => Err(Halt::Failed("dispatch write unavailable".into())),
            }
        } else {
            self.book.claim(kind, key, ttl_ms)
        }
    }
}

#[test]
fn a_fresh_task_without_a_recordable_dispatch_is_refused_without_partial_open_writes() {
    for refusal in [Refusal::Taken, Refusal::Store] {
        let mut rec = RefusesDispatch {
            book: Book::default(),
            refusal,
        };
        let earlier = Write {
            kind: KIND_PUSH_CONFIG,
            key: task_key(ALICE, "another-task"),
            value: b"earlier unrelated write".to_vec(),
        };
        let mut out = vec![earlier.clone()];
        let result = open(
            &mut rec,
            &step(ALICE, 100),
            row("fresh", 100),
            "planner",
            &mut out,
        );
        assert!(
            matches!(result, Err(Halt::Failed(_))),
            "an empty-agent genesis must never be reported as an opened relay task: {result:?}"
        );
        assert_eq!(
            out,
            vec![earlier.clone()],
            "withdraw only writes made by this failed open"
        );
        rec.book.apply(&out);
        assert!(get(&mut rec, ALICE, "fresh", 100).unwrap().is_none());
        assert!(rec
            .book
            .list(KIND_TASK_EVENT, &task_key(ALICE, "fresh"))
            .unwrap()
            .is_empty());
        assert_eq!(
            rec.book.value(KIND_PUSH_CONFIG, &earlier.key),
            Some(&earlier.value)
        );
    }
}

#[test]
fn a_successful_fresh_open_keeps_its_genesis_and_dispatch_and_their_verified_sequence() {
    let mut book = Book::default();
    let mut out = Vec::new();
    let opened = open(
        &mut book,
        &step(ALICE, 100),
        row("fresh", 100),
        "planner",
        &mut out,
    )
    .unwrap();
    assert_eq!(opened.agent_id, "planner");
    book.apply(&out);
    let held = get(&mut book, ALICE, "fresh", 100).unwrap().unwrap();
    assert_eq!(held.row, opened);
    assert_eq!(held.next_seq, 3);
    assert_eq!(event(&book, ALICE, "fresh", 1).kind, EV_SUBMITTED);
    assert_eq!(event(&book, ALICE, "fresh", 2).kind, EV_DELEGATED);
    assert!(restore(&mut book).unwrap().chain_breaks.is_empty());
}
