// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CARD FETCH'S PRE-CHECK FAILS CLOSED (docs/security.md, the A2A card fetch: every hop is
//! guarded): a door that has a connector but no host services has no destination judgement to ask,
//! and a hop no judgement admitted is never dialled. The host here is a fake whose connector counts
//! every dial; it lends the door its connector and nothing else.

use std::cell::Cell;

use busbar_contract::abi::host::conn::connector::EstablishIn;
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::test_support::fake::{conn, FakeHost, FakeService, ServiceCall};

use super::*;

thread_local! {
    /// The dials this thread's fake connector was asked for.
    static DIALS: Cell<usize> = const { Cell::new(0) };
}

/// The connector: every dial is counted and fails (nothing listens).
struct Dial;
impl FakeService for Dial {
    type In = EstablishIn;
    fn serve(_: &mut ServiceCall<EstablishIn>) -> Outcome {
        DIALS.with(|d| d.set(d.get() + 1));
        Outcome::Failed
    }
}

/// A card fetch of `planner` by a door that holds a connector and NO host services is refused,
/// and nothing is dialled. RED before the fix: the pre-check answered "admitted" with no
/// judgement, and both discovery paths were dialled.
#[test]
fn a_card_fetch_without_host_services_is_refused() {
    let fake: &'static FakeHost = Box::leak(Box::new(FakeHost::new().serve(conn::ESTABLISH, Dial)));
    let tables = Box::leak(Box::new(fake.lent()));
    let plane = A2aDoor {
        host: Some(Host::of(tables)),
        services: None,
        ..A2aDoor::default()
    };
    let def: crate::a2a::config::AgentDefCfg = serde_json::from_value(serde_json::json!({
        "url": "https://agent.example/a2a",
        "pin": {"mechanism": "unpinned"},
    }))
    .unwrap();
    let at = LookAt {
        plane: &plane,
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

thread_local! {
    /// The destination judgements this thread's fake host was asked for.
    static JUDGED: Cell<usize> = const { Cell::new(0) };
}

/// The destination judgement: the first host it is asked about is a loopback name, every later one
/// does not resolve, so the canonical path and the legacy path are refused in different words.
struct LoopbackThenUnresolvable;
impl FakeService for LoopbackThenUnresolvable {
    type In = busbar_contract::abi::host::service::DestJudgeIn;
    fn serve(call: &mut ServiceCall<busbar_contract::abi::host::service::DestJudgeIn>) -> Outcome {
        let n = JUDGED.with(|j| {
            j.set(j.get() + 1);
            j.get()
        });
        call.set_value(if n == 1 {
            busbar_contract::abi::host::service::DEST_INTERNAL
        } else {
            busbar_contract::abi::host::service::DEST_UNRESOLVABLE
        });
        Outcome::Ready
    }
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
    let fake: &'static FakeHost = Box::leak(Box::new(
        FakeHost::new()
            .serve(
                busbar_contract::abi::sdk::test_support::fake::host::DEST_JUDGE,
                LoopbackThenUnresolvable,
            )
            .serve(conn::ESTABLISH, Dial),
    ));
    let tables = Box::leak(Box::new(fake.lent()));
    let plane = A2aDoor {
        host: Some(Host::of(tables)),
        services: busbar_contract::abi::sdk::Services::of(tables),
        ..A2aDoor::default()
    };
    let at = LookAt {
        plane: &plane,
        ticket: Ticket {
            slot: 4,
            generation: 1,
        },
        base: 0,
    };
    JUDGED.with(|j| j.set(0));
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
}

/// G1-44: THE RELAY'S GUARD NAMES WHY IT REFUSED: the caller reads the hop's fixed words, and the
/// operator reads the refusal's own sentence in a diagnostic (here, the plaintext scheme).
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
    let (sent, heard) = std::sync::mpsc::channel();
    let refused = tracing::subscriber::with_default(crate::tests::capture::Capture(sent), || {
        guard_relay(&reach, &mut hop, &mut pass, url, &planner_def(url))
    });
    assert!(
        matches!(refused, Poll::Ready(Some(_))),
        "the hop is refused"
    );
    let lines: Vec<String> = heard.try_iter().map(|(_, line)| line).collect();
    assert!(
        lines.iter().any(|l| l.contains("uses scheme `http`")),
        "{lines:?}"
    );
}
