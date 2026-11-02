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
    fn claim(&mut self, _: &str, _: &str, _: u64) -> Result<bool, Halt> {
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
            2,
            "the exact old/new owners both retire"
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
