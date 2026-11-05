// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::tests::raw_custody_probe::{Probe, SECRET};

#[derive(Clone, Copy)]
enum End {
    Applied,
    Conflict,
    Pending,
    Refused,
    Unwind,
}
struct Host(End);
impl Records for Host {
    fn get(&mut self, kind: &str, _: &str) -> Result<Option<Vec<u8>>, Halt> {
        if kind == crate::records::KIND_TASK_QUOTA {
            return Ok(Some(br#"{"version":1,"epoch":1,"active":1}"#.to_vec()));
        }
        assert_eq!(kind, KIND_TASK);
        Ok(Some(
            serde_json::to_vec(&HeldTask {
                row: tests::row("task", 100),
                next_seq: 3,
            })
            .unwrap(),
        ))
    }
    fn list(&mut self, _: &str, _: &str) -> Result<Vec<(String, Vec<u8>)>, Halt> {
        unreachable!()
    }
    fn observe_chain_life(&mut self, _: &str, _: &str) -> Result<Option<Vec<u8>>, Halt> {
        Ok(None)
    }
    fn publish(
        &mut self,
        predicates: &[Predicate],
        _: &[ChainLife],
        writes: &[Write],
    ) -> Result<bool, Halt> {
        assert_eq!(predicates[1].expected.as_deref(), Some(SECRET));
        assert_eq!(writes[0].value, SECRET);
        match self.0 {
            End::Applied => Ok(true),
            End::Conflict => Ok(false),
            End::Pending => Err(Halt::Pending),
            End::Refused => Err(Halt::Failed("refused".into())),
            End::Unwind => panic!("injected host unwind"),
        }
    }
}

#[test]
fn config_publication_keeps_old_and_new_raw_credentials_wiping_across_every_outcome() {
    for end in [
        End::Applied,
        End::Conflict,
        End::Pending,
        End::Refused,
        End::Unwind,
    ] {
        let mut host = Host(end);
        let probe = Probe::start();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            write_config(
                &mut host,
                &tests::step(tests::ALICE, 100),
                "task",
                Some(SECRET.to_vec()),
                SECRET.to_vec(),
            )
        }));
        assert_eq!(result.is_err(), matches!(end, End::Unwind));
        assert_eq!(
            probe.retirements(),
            4,
            "both input owners and every guarded transaction copy retire wiped"
        );
        probe.checkpoint();
    }
}

#[test]
fn refused_config_identity_retires_inputs_before_any_host_crossing() {
    let probe = Probe::start();
    assert!(write_config(
        &mut Host(End::Unwind),
        &tests::step("invalid", 100),
        "task",
        Some(SECRET.to_vec()),
        SECRET.to_vec()
    )
    .is_err());
    assert_eq!(probe.retirements(), 2);
    probe.checkpoint();
}

/// A held task whose row carries the custody canary, active so no sweep retires it.
fn canary_book() -> tests::Book {
    let mut book = tests::Book::default();
    let mut row = tests::row("task", 100);
    row.push_callback = std::str::from_utf8(SECRET).unwrap().to_string();
    book.hold(tests::ALICE, &HeldTask { row, next_seq: 2 });
    book
}

/// RED before the fix: the task-row bytes a read, a listing, a restore or a sweep took from the host
/// were dropped as plain heap bytes, unlike the same bytes in a predicate or a write; every path now
/// retires them through the wiping owner.
#[test]
fn task_row_bytes_every_read_path_takes_are_wiped() {
    type ReadPath = fn(&mut tests::Book);
    let reads: [(&str, ReadPath); 4] = [
        ("get", |book| {
            assert!(get(book, tests::ALICE, "task", 100).unwrap().is_some());
        }),
        ("list", |book| {
            assert_eq!(list(book, tests::ALICE, 100).unwrap().len(), 1);
        }),
        ("restore", |book| {
            assert_eq!(restore(book).unwrap().active, 1);
        }),
        ("retention_sweep", |book| {
            assert_eq!(retention_sweep(book, 100, 32, &mut Vec::new()).unwrap(), 0);
        }),
    ];
    for (path, read) in reads {
        let mut book = canary_book();
        let probe = Probe::start();
        read(&mut book);
        assert!(
            probe.retirements() >= 1,
            "{path}: the row bytes retire wiped"
        );
        probe.checkpoint();
    }
}
