// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::tests::raw_custody_probe::{Probe, SECRET};
use busbar_contract::abi::host::service::{HostSlots, SERVICES};
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables};
use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::test_support::zeroed;

/// `Via::issue` requires services, but these tests answer through its closure alone.
#[allow(unsafe_code)]
fn unused_scratch_services() -> Services {
    let slots = HostSlots {
        size: std::mem::size_of::<HostSlots>() as u32,
        slots: SERVICES,
        ..zeroed()
    };
    let tables = HostTables {
        size: std::mem::size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx::NONE,
        wake: None,
        conns: std::ptr::null(),
        services: &slots,
        io: std::ptr::null(),
    };
    // SAFETY: both complete, aligned tables remain initialized and unchanged throughout this
    // call. The sealed zeroed HostSlots has only None callbacks; every other nested pointer is
    // NULL. Services::from_raw copies the table before these locals expire, so no borrowed pointer or
    // callback survives the call. The test closures perform the read, Pending and unwind directly.
    unsafe { Services::from_raw(&tables) }
        .expect("the complete service table is present, with every slot unsupported")
}

#[test]
fn records_scratch_growth_and_pending_release_retire_each_initialized_owner() {
    let host = Host::NONE;
    let grown = Keyed::new();
    let ticket = Ticket {
        slot: 7,
        generation: 1,
    };
    let mut via = Via::new(&host, Some(unused_scratch_services()), ticket, 0, &grown);
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
    let host = Host::NONE;
    let grown = Keyed::new();
    let probe = Probe::start();
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut via = Via::new(
            &host,
            Some(unused_scratch_services()),
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
