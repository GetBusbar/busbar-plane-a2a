// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TRUST IS RE-CHECKED BEFORE EVERY OUTBOUND REQUEST, busbar's own included (docs/a2a.md "Trust
//! re-checked before every outbound request"): the requests busbar ORIGINATES to an agent (the
//! push-config mirror, the `ListTasks` refresh) go through [`drive_originated`], and an agent the
//! kernel's trust book does not serve (quarantined, its card changed, never approved) is sent
//! nothing. The host here is a fake whose destination judgement admits the agent and whose
//! connector counts every dial, so a request that left is a counted ESTABLISH.

use std::cell::Cell;

use busbar_contract::abi::host::conn::connector::EstablishIn;
use busbar_contract::abi::host::service::{self as svc, DestJudgeIn, TrustServesIn, DEST_ALLOWED};
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::test_support::fake::{
    conn, host, FakeHost, FakeService, ServiceCall,
};
use busbar_contract::abi::sdk::Services;

use super::*;

thread_local! {
    /// The dials this thread's fake connector was asked for.
    static DIALS: Cell<usize> = const { Cell::new(0) };
}

/// The agent's url judged: admitted, as the open web's guard admits a public name.
struct Admitted;
impl FakeService for Admitted {
    type In = DestJudgeIn;
    fn serve(call: &mut ServiceCall<DestJudgeIn>) -> Outcome {
        call.set_value(DEST_ALLOWED);
        Outcome::Ready
    }
}

/// The kernel's trust book: the agent is QUARANTINED.
struct Quarantined;
impl FakeService for Quarantined {
    type In = TrustServesIn;
    fn serve(call: &mut ServiceCall<TrustServesIn>) -> Outcome {
        call.set_value(svc::DISTRUST_QUARANTINED);
        Outcome::Ready
    }
}

/// The kernel's trust book: the agent is served.
struct Serving;
impl FakeService for Serving {
    type In = TrustServesIn;
    fn serve(call: &mut ServiceCall<TrustServesIn>) -> Outcome {
        call.set_value(svc::DISTRUST_NONE);
        Outcome::Ready
    }
}

/// The connector: every dial is counted and fails (nothing listens), so the request is not
/// answered, which is all these cases need to know.
struct Dial;
impl FakeService for Dial {
    type In = EstablishIn;
    fn serve(_: &mut ServiceCall<EstablishIn>) -> Outcome {
        DIALS.with(|d| d.set(d.get() + 1));
        Outcome::Failed
    }
}

const TICKET: Ticket = Ticket {
    slot: 2,
    generation: 5,
};

/// A door opened over `fake`: its host and its services, nothing else.
fn door_over(fake: &'static FakeHost) -> A2aDoor {
    let tables = Box::leak(Box::new(fake.lent()));
    A2aDoor {
        host: Some(Host::of(tables)),
        services: Services::of(tables),
        ..A2aDoor::default()
    }
}

fn quarantined_host() -> &'static FakeHost {
    Box::leak(Box::new(
        FakeHost::new()
            .serve(host::DEST_JUDGE, Admitted)
            .serve(host::TRUST_SERVES, Quarantined)
            .serve(conn::ESTABLISH, Dial),
    ))
}

fn serving_host() -> &'static FakeHost {
    Box::leak(Box::new(
        FakeHost::new()
            .serve(host::DEST_JUDGE, Admitted)
            .serve(host::TRUST_SERVES, Serving)
            .serve(conn::ESTABLISH, Dial),
    ))
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
/// the agent's trust as a relayed hop is. RED before the fix: the mirror dialled it.
#[test]
fn a_quarantined_agent_is_sent_no_mirrored_push_config() {
    let plane = door_over(quarantined_host());
    assert_eq!(
        mirror_dials(&plane),
        0,
        "a quarantined agent was dialled for busbar's mirrored push config"
    );
}

/// A QUARANTINED agent is asked no `ListTasks` refresh. RED before the fix: it was dialled.
#[test]
fn a_quarantined_agent_is_asked_no_list_tasks_refresh() {
    let plane = door_over(quarantined_host());
    assert_eq!(
        list_dials(&plane),
        0,
        "a quarantined agent was dialled for busbar's ListTasks refresh"
    );
}

/// The control: an agent the trust book serves IS dialled for both, so the cases above see a dial
/// when one is made.
#[test]
fn a_serving_agent_is_dialled_for_its_mirror_and_its_refresh() {
    let plane = door_over(serving_host());
    assert!(mirror_dials(&plane) >= 1, "the mirror dialled the agent");
    assert_eq!(list_dials(&plane), 1, "the refresh dialled the agent");
}
