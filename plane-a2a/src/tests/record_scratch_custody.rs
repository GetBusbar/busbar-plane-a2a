// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::tests::raw_custody_probe::{Probe, SECRET};
use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::test_support::fake::FakeHost;

#[test]
fn records_scratch_growth_and_pending_release_retire_each_initialized_owner() {
    let fake: &'static FakeHost = Box::leak(Box::new(FakeHost::new()));
    let tables = fake.lent();
    let host = Host::of(&tables);
    let grown = Keyed::new();
    let ticket = Ticket {
        slot: 7,
        generation: 1,
    };
    let mut via = Via::new(&host, Services::of(&tables), ticket, 0, &grown);
    let read: Result<(), Halt> = via.issue((SECRET.len(), 0), |_, _, bytes, _| {
        bytes.copy_from_slice(SECRET);
        Poll::Ready(Ok(()))
    });
    assert_eq!(read, Ok(()));
    let probe = Probe::start();
    let pending: Result<(), Halt> = via.issue((SECRET.len() * 4, 0), |_, _, bytes, _| {
        assert_eq!(
            &bytes[..SECRET.len()],
            SECRET,
            "live scratch remains intact after growth"
        );
        Poll::Pending
    });
    assert_eq!(pending, Err(Halt::Pending));
    assert_eq!(
        probe.retirements(),
        1,
        "growth retires the initialized old allocation"
    );
    probe.checkpoint();
    drop(via);
    assert_eq!(
        probe.retirements(),
        2,
        "Pending releases the new scratch owner"
    );
    probe.checkpoint();
}

#[test]
fn records_scratch_is_wiped_when_a_host_read_unwinds() {
    let fake: &'static FakeHost = Box::leak(Box::new(FakeHost::new()));
    let tables = fake.lent();
    let host = Host::of(&tables);
    let grown = Keyed::new();
    let probe = Probe::start();
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut via = Via::new(
            &host,
            Services::of(&tables),
            Ticket {
                slot: 8,
                generation: 1,
            },
            0,
            &grown,
        );
        let _: Result<(), Halt> = via.issue((SECRET.len(), 0), |_, _, bytes, _| {
            bytes.copy_from_slice(SECRET);
            panic!("injected host unwind");
        });
    }));
    assert!(unwind.is_err());
    assert_eq!(probe.retirements(), 1);
    probe.checkpoint();
}
