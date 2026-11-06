// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn sweep_cadence_bounds_backlog_scans_and_drains_full_budget_backlogs() {
    let gate = SweepGate::default();
    assert!(
        gate.due(100),
        "the first submit sweeps, including after restart"
    );
    gate.swept(100, 0, SWEEP_BUDGET);
    assert!(!gate.due(100));
    assert!(!gate.due(100 + SWEEP_INTERVAL_SECS - 1));
    assert!(gate.due(100 + SWEEP_INTERVAL_SECS));
    gate.swept(130, SWEEP_BUDGET, SWEEP_BUDGET);
    assert!(
        gate.due(131),
        "a full-budget sweep may leave a backlog; a later submit drains it"
    );
    gate.swept(131, SWEEP_BUDGET - 1, SWEEP_BUDGET);
    assert!(!gate.due(130));
    assert!(gate.due(131 + SWEEP_INTERVAL_SECS));
    assert!(
        SweepGate::default().due(130),
        "restart does not persist a stale delay"
    );
}

#[test]
fn sweep_count_matches_retired_tasks_and_keeps_active_rows_and_chains() {
    let mut book = Book::default();
    for task in ["done-a", "done-b", "active"] {
        submitted(&mut book, ALICE, task, 100);
        if task != "active" {
            let mut out = Vec::new();
            transition(
                &mut book,
                &step(ALICE, 100),
                task,
                TaskState::Completed,
                &mut out,
            )
            .unwrap();
            book.apply(&out);
        }
    }
    for expected in [1, 1, 0] {
        let mut out = Vec::new();
        let before = book.publications.len();
        let count = retention_sweep(&mut book, 101 + TERMINAL_TTL_SECS, 1, &mut out).unwrap();
        assert_eq!(count, expected);
        assert_eq!(
            book.publications[before..]
                .iter()
                .map(Vec::len)
                .sum::<usize>(),
            expected * 5,
            "task, config and chain tombstones plus both quota records form one retirement"
        );
        assert!(out.is_empty(), "retirement is already atomically committed");
        book.apply(&out);
    }
    assert!(get(&mut book, ALICE, "active", 101 + TERMINAL_TTL_SECS)
        .unwrap()
        .is_some());
    assert_eq!(
        book.list(KIND_TASK_EVENT, &task_key(ALICE, "active"))
            .unwrap()
            .len(),
        1
    );
    for task in ["done-a", "done-b"] {
        assert!(book.value(KIND_TASK, &task_key(ALICE, task)).is_none());
        assert!(book
            .list(KIND_TASK_EVENT, &task_key(ALICE, task))
            .unwrap()
            .is_empty());
    }
}

#[test]
fn reserving_a_sweep_excludes_concurrent_starts_and_backs_off_failures() {
    let gate = SweepGate::default();
    assert!(gate.due(100));
    assert!(!gate.due(100));
    assert!(!gate.due(129));
    assert!(gate.due(130));
}
