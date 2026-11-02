// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TRUST IS RE-CHECKED BEFORE EVERY OUTBOUND REQUEST, busbar's own included (docs/a2a.md "Trust

use std::cell::Cell;
use std::ffi::c_void;
use std::mem::size_of;

use busbar_contract::abi::host::conn::connector::{self, ConnectorSlots, EstablishIn};
use busbar_contract::abi::host::service::{self as svc, ServiceHead, ServiceOut};
use busbar_contract::abi::mechanism::call::{Outcome, RawOutcome};
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables, Ticket};
use busbar_contract::abi::sdk::Services;
use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::test_support::{lend, zeroed};

use super::*;

thread_local! {
    /// The dials this thread's test connector was asked for.
    static DIALS: Cell<usize> = const { Cell::new(0) };
    static VERDICT: Cell<u64> = const { Cell::new(svc::DISTRUST_NONE) };
}

/// The agent's public destination is admitted by the concrete destination service.
#[allow(unsafe_code)]
unsafe extern "C" fn admitted(
    ctx: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    if ctx != HostCtx::NONE || input.is_null() || out.is_null() {
        return RawOutcome::of(Outcome::Refused);
    }
    // SAFETY: the actual SDK service call lends an initialized ServiceHead for this crossing.
    // Check its exact operation and input prefix before accepting this concrete service.
    let head = unsafe { input.cast::<ServiceHead>().read_unaligned() };
    if svc::check_head(&head, svc::op::DEST_JUDGE, size_of::<svc::DestJudgeIn>()).is_err() {
        return RawOutcome::of(Outcome::Refused);
    }
    // SAFETY: the SDK owns and exclusively lends out, including its readable leading size.
    // Only the prefix it advertises may be written; no output or nested buffer is retained.
    let Some(lent) = (unsafe { svc::lent_out(out) }) else {
        return RawOutcome::of(Outcome::Refused);
    };
    let outcome = RawOutcome::of(Outcome::Ready);
    let value = svc::DEST_ALLOWED;
    // SAFETY: lent_out capped this live, exclusively writable SDK output at our layout.
    // The scalar answer has no borrowed data, and write_out touches only that lent prefix.
    unsafe {
        svc::write_out(
            out,
            ServiceOut {
                outcome,
                value,
                ..ServiceOut::ZERO
            },
            lent,
        );
    }
    outcome
}

/// The trust service quarantines the agent.
#[allow(unsafe_code)]
unsafe extern "C" fn quarantined(
    ctx: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    if ctx != HostCtx::NONE || input.is_null() || out.is_null() {
        return RawOutcome::of(Outcome::Refused);
    }
    // SAFETY: the actual SDK service call lends an initialized ServiceHead for this crossing.
    // Check its exact operation and input prefix before accepting this concrete service.
    let head = unsafe { input.cast::<ServiceHead>().read_unaligned() };
    if svc::check_head(
        &head,
        svc::op::TRUST_SERVES,
        size_of::<svc::TrustServesIn>(),
    )
    .is_err()
    {
        return RawOutcome::of(Outcome::Refused);
    }
    // SAFETY: the SDK owns and exclusively lends out, including its readable leading size.
    // Only the prefix it advertises may be written; no output or nested buffer is retained.
    let Some(lent) = (unsafe { svc::lent_out(out) }) else {
        return RawOutcome::of(Outcome::Refused);
    };
    let outcome = RawOutcome::of(Outcome::Ready);
    let value = svc::DISTRUST_QUARANTINED;
    // SAFETY: lent_out capped this live, exclusively writable SDK output at our layout.
    // The scalar answer has no borrowed data, and write_out touches only that lent prefix.
    unsafe {
        svc::write_out(
            out,
            ServiceOut {
                outcome,
                value,
                ..ServiceOut::ZERO
            },
            lent,
        );
    }
    outcome
}

/// The trust service serves the agent.
#[allow(unsafe_code)]
unsafe extern "C" fn serving(
    ctx: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    if ctx != HostCtx::NONE || input.is_null() || out.is_null() {
        return RawOutcome::of(Outcome::Refused);
    }
    // SAFETY: the actual SDK service call lends an initialized ServiceHead for this crossing.
    // Check its exact operation and input prefix before accepting this concrete service.
    let head = unsafe { input.cast::<ServiceHead>().read_unaligned() };
    if svc::check_head(
        &head,
        svc::op::TRUST_SERVES,
        size_of::<svc::TrustServesIn>(),
    )
    .is_err()
    {
        return RawOutcome::of(Outcome::Refused);
    }
    // SAFETY: the SDK owns and exclusively lends out, including its readable leading size.
    // Only the prefix it advertises may be written; no output or nested buffer is retained.
    let Some(lent) = (unsafe { svc::lent_out(out) }) else {
        return RawOutcome::of(Outcome::Refused);
    };
    let outcome = RawOutcome::of(Outcome::Ready);
    let value = svc::DISTRUST_NONE;
    // SAFETY: lent_out capped this live, exclusively writable SDK output at our layout.
    // The scalar answer has no borrowed data, and write_out touches only that lent prefix.
    unsafe {
        svc::write_out(
            out,
            ServiceOut {
                outcome,
                value,
                ..ServiceOut::ZERO
            },
            lent,
        );
    }
    outcome
}

/// The trust service returns this thread's exact verdict.
#[allow(unsafe_code)]
unsafe extern "C" fn verdict(
    ctx: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    if ctx != HostCtx::NONE || input.is_null() || out.is_null() {
        return RawOutcome::of(Outcome::Refused);
    }
    // SAFETY: the actual SDK service call lends an initialized ServiceHead for this crossing.
    // Check its exact operation and input prefix before accepting this concrete service.
    let head = unsafe { input.cast::<ServiceHead>().read_unaligned() };
    if svc::check_head(
        &head,
        svc::op::TRUST_SERVES,
        size_of::<svc::TrustServesIn>(),
    )
    .is_err()
    {
        return RawOutcome::of(Outcome::Refused);
    }
    // SAFETY: the SDK owns and exclusively lends out, including its readable leading size.
    // Only the prefix it advertises may be written; no output or nested buffer is retained.
    let Some(lent) = (unsafe { svc::lent_out(out) }) else {
        return RawOutcome::of(Outcome::Refused);
    };
    let outcome = RawOutcome::of(Outcome::Ready);
    let value = VERDICT.with(Cell::get);
    // SAFETY: lent_out capped this live, exclusively writable SDK output at our layout.
    // The scalar answer has no borrowed data, and write_out touches only that lent prefix.
    unsafe {
        svc::write_out(
            out,
            ServiceOut {
                outcome,
                value,
                ..ServiceOut::ZERO
            },
            lent,
        );
    }
    outcome
}

/// The trust service is present but its call fails.
#[allow(unsafe_code)]
unsafe extern "C" fn unavailable(
    ctx: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    if ctx != HostCtx::NONE || input.is_null() || out.is_null() {
        return RawOutcome::of(Outcome::Refused);
    }
    // SAFETY: the actual SDK service call lends an initialized ServiceHead for this crossing.
    // Check its exact operation and input prefix before accepting this concrete service.
    let head = unsafe { input.cast::<ServiceHead>().read_unaligned() };
    if svc::check_head(
        &head,
        svc::op::TRUST_SERVES,
        size_of::<svc::TrustServesIn>(),
    )
    .is_err()
    {
        return RawOutcome::of(Outcome::Refused);
    }
    // SAFETY: the SDK owns and exclusively lends out, including its readable leading size.
    // Only the prefix it advertises may be written; no output or nested buffer is retained.
    let Some(lent) = (unsafe { svc::lent_out(out) }) else {
        return RawOutcome::of(Outcome::Refused);
    };
    let outcome = RawOutcome::of(Outcome::Failed);
    let value = 0;
    // SAFETY: lent_out capped this live, exclusively writable SDK output at our layout.
    // The scalar answer has no borrowed data, and write_out touches only that lent prefix.
    unsafe {
        svc::write_out(
            out,
            ServiceOut {
                outcome,
                value,
                ..ServiceOut::ZERO
            },
            lent,
        );
    }
    outcome
}

/// The connector counts every dial and fails it: no request reaches a backend.
#[allow(unsafe_code)]
unsafe extern "C" fn dial(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    if ctx != HostCtx::NONE || input.is_null() || out.is_null() {
        return RawOutcome::of(Outcome::Refused);
    }
    // SAFETY: the actual SDK service call lends an initialized ServiceHead for this crossing.
    // Check its exact operation and input prefix before accepting this concrete service.
    let head = unsafe { input.cast::<ServiceHead>().read_unaligned() };
    if svc::check_head(
        &head,
        connector::service::ESTABLISH,
        size_of::<EstablishIn>(),
    )
    .is_err()
    {
        return RawOutcome::of(Outcome::Refused);
    }
    // SAFETY: the SDK owns and exclusively lends out, including its readable leading size.
    // Only the prefix it advertises may be written; no output or nested buffer is retained.
    let Some(lent) = (unsafe { svc::lent_out(out) }) else {
        return RawOutcome::of(Outcome::Refused);
    };
    DIALS.with(|d| d.set(d.get() + 1));
    let outcome = RawOutcome::of(Outcome::Failed);
    let value = 0;
    // SAFETY: lent_out capped this live, exclusively writable SDK output at our layout.
    // The scalar answer has no borrowed data, and write_out touches only that lent prefix.
    unsafe {
        svc::write_out(
            out,
            ServiceOut {
                outcome,
                value,
                ..ServiceOut::ZERO
            },
            lent,
        );
    }
    outcome
}

const TICKET: Ticket = Ticket {
    slot: 2,
    generation: 5,
};

/// Copy this test's concrete tables into the actual SDK handles, without retaining a loan.
#[allow(unsafe_code)]
fn door_over(trust_serves: Option<svc::ServiceFn>) -> A2aDoor {
    let conns = ConnectorSlots {
        size: size_of::<ConnectorSlots>() as u32,
        slots: connector::SERVICES,
        establish: Some(dial),
        ..zeroed()
    };
    let services = svc::HostSlots {
        size: size_of::<svc::HostSlots>() as u32,
        slots: svc::SERVICES,
        dest_judge: Some(admitted),
        trust_serves,
        ..zeroed()
    };
    let tables = HostTables {
        size: size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx::NONE,
        wake: None,
        conns: &conns,
        services: &services,
        io: std::ptr::null(),
    };
    // SAFETY: both complete, initialized nested tables remain live through both SDK
    // constructors, which copy their advertised prefixes. Every non-NULL callback is a
    // static function, validates NONE context before state access, and retains no raw
    // input/output pointer. Other slots are NULL; only existing thread-local Cells persist.
    let tables = unsafe { lend(&tables) };
    A2aDoor {
        host: Some(Host::of(tables)),
        services: Services::of(tables),
        ..A2aDoor::default()
    }
}

fn originated() -> crate::mirror::Originated {
    crate::mirror::Originated {
        agent: "planner".into(),
        url: "https://agent.example/a2a".into(),
        allow_private: false,
        binding: crate::binding::Binding::JsonRpc,
        version: "1.0",
        seq: 0,
        exchange: None,
    }
}

/// The mirror of a caller's push config onto `planner`, driven to its end; the dials it made.
fn mirror_dials(plane: &A2aDoor) -> usize {
    DIALS.with(|d| d.set(0));
    let mut flight = crate::mirror::Flight {
        stage: crate::mirror::Stage::Mirror,
        method: crate::mirror::method::CREATE_PUSH_CONFIG,
        backend_task: "b-1".into(),
        create: serde_json::json!({}),
        hop: originated(),
    };
    assert!(drive_mirror(plane, TICKET, &mut flight).is_ready());
    DIALS.with(Cell::get)
}

/// The `ListTasks` refresh busbar asks of `planner`; the dials it made.
fn list_dials(plane: &A2aDoor) -> usize {
    DIALS.with(|d| d.set(0));
    let mut hop = originated();
    let landed = drive_originated(
        plane,
        TICKET,
        &mut hop,
        crate::mirror::LIST_TASKS,
        &serde_json::json!({}),
    );
    assert!(landed.is_ready());
    DIALS.with(Cell::get)
}

/// A QUARANTINED agent is sent no mirrored push config: the mirror busbar originates is held to
#[test]
fn a_quarantined_agent_is_sent_no_mirrored_push_config() {
    let plane = door_over(Some(quarantined));
    assert_eq!(
        mirror_dials(&plane),
        0,
        "a quarantined agent was dialled for busbar's mirrored push config"
    );
}

/// A QUARANTINED agent is asked no `ListTasks` refresh. RED before the fix: it was dialled.
#[test]
fn a_quarantined_agent_is_asked_no_list_tasks_refresh() {
    let plane = door_over(Some(quarantined));
    assert_eq!(
        list_dials(&plane),
        0,
        "a quarantined agent was dialled for busbar's ListTasks refresh"
    );
}

/// The control: an agent the trust book serves IS dialled for both, so the cases above see a dial
#[test]
fn a_serving_agent_is_dialled_for_its_mirror_and_its_refresh() {
    let plane = door_over(Some(serving));
    assert!(mirror_dials(&plane) >= 1, "the mirror dialled the agent");
    assert_eq!(list_dials(&plane), 1, "the refresh dialled the agent");
}

#[test]
fn every_nonserving_trust_verdict_refuses_both_originated_requests() {
    let plane = door_over(Some(verdict));
    for verdict in [
        svc::DISTRUST_UNKNOWN,
        svc::DISTRUST_UNSIGHTED,
        svc::DISTRUST_QUARANTINED,
        svc::DISTRUST_NOT_APPROVED,
        svc::DISTRUST_CHANGED,
        svc::DISTRUST_UNKNOWN_ITEM,
    ] {
        VERDICT.with(|v| v.set(verdict));
        assert_eq!(mirror_dials(&plane), 0, "mirror, distrust {verdict}");
        assert_eq!(list_dials(&plane), 0, "refresh, distrust {verdict}");
    }
    VERDICT.with(|v| v.set(svc::DISTRUST_NONE));
    assert!(
        mirror_dials(&plane) >= 1,
        "the same host serves the positive control"
    );
    assert_eq!(list_dials(&plane), 1);
}

#[test]
fn failed_sightings_and_unavailable_trust_services_refuse_originated_requests() {
    let plane = door_over(Some(serving));
    plane.trust.insert(
        "planner".into(),
        crate::card_trust::TrustStanding {
            sighting: crate::card_trust::Sighting::Failed("the last card look failed".into()),
            ..Default::default()
        },
    );
    assert_eq!(mirror_dials(&plane), 0);
    assert_eq!(list_dials(&plane), 0);

    let trust_services: [Option<svc::ServiceFn>; 2] = [Some(unavailable), None];
    for trust_serves in trust_services {
        let plane = door_over(trust_serves);
        assert_eq!(mirror_dials(&plane), 0);
        assert_eq!(list_dials(&plane), 0);
    }
    let mut plane = door_over(Some(serving));
    plane.services = None;
    assert_eq!(mirror_dials(&plane), 0);
    assert_eq!(list_dials(&plane), 0);
}
