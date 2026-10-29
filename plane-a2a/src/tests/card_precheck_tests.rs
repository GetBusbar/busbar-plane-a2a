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
