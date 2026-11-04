// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CARD FETCH'S PRE-CHECK FAILS CLOSED (docs/security.md, the A2A card fetch: every hop is
//! guarded): a door that has a connector but no host services has no destination judgement to ask,
//! and a hop no judgement admitted is never dialled.

use std::cell::Cell;
use std::ffi::c_void;
use std::mem::size_of;

use busbar_contract::abi::host::conn::connector::{self, ConnectorSlots, EstablishIn};
use busbar_contract::abi::host::service::{self as svc, ServiceHead, ServiceOut};
use busbar_contract::abi::mechanism::call::{Outcome, RawOutcome};
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables, Ticket};
use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::test_support::zeroed;
use busbar_contract::abi::sdk::Services;

use super::*;

thread_local! {
    /// The dials this thread's test connector was asked for.
    static DIALS: Cell<usize> = const { Cell::new(0) };
}

/// The connector counts every actual dial and fails it: nothing listens.
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

/// Copy this test's concrete tables into the actual SDK handles, without retaining a loan.
#[allow(unsafe_code)]
fn card_door(with_judgements: bool) -> A2aDoor {
    let conns = ConnectorSlots {
        size: size_of::<ConnectorSlots>() as u32,
        slots: connector::SERVICES,
        establish: Some(dial),
        ..zeroed()
    };
    let services = svc::HostSlots {
        size: size_of::<svc::HostSlots>() as u32,
        slots: svc::SERVICES,
        dest_judge: with_judgements.then_some(judge),
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
    // SAFETY: both complete, initialized nested tables remain live during this snapshot.
    // Their non-NULL slots are static functions validating NONE context and their exact input
    // prefix. They retain no raw pointers; the SDK copies slots, and all other slots are NULL.
    let host = unsafe { Host::from_raw(&tables) };
    let services = if with_judgements {
        // SAFETY: the complete services table is still live, with the same validated static
        // callbacks. This constructor copies it; no table pointer or loan escapes this call.
        unsafe { Services::from_raw(&tables) }
    } else {
        None
    };
    A2aDoor {
        host: Some(host),
        services,
        ..A2aDoor::default()
    }
}

/// A card fetch of `planner` by a door that holds a connector and NO host services is refused, and
/// nothing is dialled.
#[test]
fn a_card_fetch_without_host_services_is_refused() {
    let plane = card_door(false);
    let def: crate::a2a::config::AgentDefCfg = serde_json::from_value(serde_json::json!({
        "url": "https://agent.example/a2a",
        "pin": {"mechanism": "unpinned"},
    }))
    .unwrap();
    let at = LookAt {
        plane: &plane,
        generation: 1,
        ticket: Ticket {
            slot: 4,
            generation: 1,
        },
        base: 0,
    };
    DIALS.with(|d| d.set(0));
    let Ok((card, _, _)) = fetch_card(&at, "planner", &def, None) else {
        panic!("the fetch parked with nothing in flight");
    };
    assert_eq!(DIALS.with(Cell::get), 0, "an unjudged card hop was dialled");
    assert!(card.is_err(), "the fetch is refused: {card:?}");
}

/// G1-44, from protected 5ca6853: preserve the operator's reason beside the caller's fixed refusal.
#[test]
fn a_refused_relay_endpoint_is_named_in_a_diagnostic() {
    let plane = A2aDoor::default();
    let reach = Reach {
        plane: &plane,
        ticket: Ticket {
            slot: 4,
            generation: 1,
        },
    };
    let mut hop = Hop::new(serde_json::json!(1), "1.0");
    let mut pass = crate::task_door::Pass::default();
    let url = "http://agent.example/a2a";
    let def = serde_json::from_value(serde_json::json!({
        "url": url, "pin": {"mechanism": "unpinned"}
    }))
    .unwrap();
    let (sent, heard) = std::sync::mpsc::channel();
    let refused = tracing::subscriber::with_default(crate::tests::capture::Capture(sent), || {
        guard_relay(&reach, &mut hop, &mut pass, url, &def, 1)
    });
    assert!(matches!(refused, Poll::Ready(Some(_))));
    assert!(
        hop.endpoint_judged.is_none(),
        "a refused endpoint carries no successful address pin"
    );
    let lines: Vec<String> = heard.try_iter().map(|(_, line)| line).collect();
    assert!(
        lines.iter().any(|l| l.contains("uses scheme `http`")),
        "{lines:?}"
    );
}

thread_local! {
    /// The destination judgements this thread's test host was asked for.
    static JUDGED: Cell<usize> = const { Cell::new(0) };
}

/// The canonical destination is a loopback name; the legacy destination does not resolve.
#[allow(unsafe_code)]
unsafe extern "C" fn judge(ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
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
    let n = JUDGED.with(|j| {
        j.set(j.get() + 1);
        j.get()
    });
    let value = if n == 1 {
        svc::DEST_INTERNAL
    } else {
        svc::DEST_UNRESOLVABLE
    };
    let outcome = RawOutcome::of(Outcome::Ready);
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

fn planner_def(url: &str) -> crate::a2a::config::AgentDefCfg {
    serde_json::from_value(serde_json::json!({
        "url": url,
        "pin": {"mechanism": "unpinned"},
    }))
    .unwrap()
}

/// G1-45: THE CANONICAL PATH'S REFUSAL IS NOT LOST TO THE LEGACY PATH'S: a card whose canonical
/// well-known path is refused for one reason and whose legacy path is refused for another reports
/// the canonical reason too.
#[test]
fn the_canonical_paths_refusal_survives_the_legacy_paths() {
    let plane = card_door(true);
    let at = LookAt {
        plane: &plane,
        generation: 1,
        ticket: Ticket {
            slot: 4,
            generation: 1,
        },
        base: 0,
    };
    JUDGED.with(|j| j.set(0));
    DIALS.with(|d| d.set(0));
    let Ok((card, _, _)) = fetch_card(
        &at,
        "planner",
        &planner_def("https://agent.example/a2a"),
        None,
    ) else {
        panic!("the fetch parked with nothing in flight");
    };
    assert_eq!(JUDGED.with(Cell::get), 2, "both paths were judged");
    let reason = card.expect_err("both paths refused");
    assert!(reason.contains("loopback name"), "{reason}");
    assert!(
        reason.contains("legacy path") && reason.contains("did not resolve"),
        "{reason}"
    );
    assert_eq!(DIALS.with(Cell::get), 0, "neither refused path is dialled");
}
