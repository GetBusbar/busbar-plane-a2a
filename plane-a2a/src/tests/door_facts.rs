// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR-DRIVEN TESTS' FACTS ARE THE DOOR'S. `tests/unit_lifetime.rs` and
//! `tests/project_session.rs` reach the plane only through `door` (the crate's one public item, and
//! its root keeps the literal `#![forbid(unsafe_code)]`, so the raw door table they drive is read in
//! those test crates, not here). The private constants they need are restated in
//! `tests/support/door_facts.rs`; this test includes that same file and holds each value to the item
//! it restates.

#[path = "../../tests/support/door_facts.rs"]
#[allow(dead_code)] // `claim` is the door-driven tests' reader, not this check's
mod stated;

#[test]
fn the_door_driven_tests_restate_the_doors_own_constants() {
    assert_eq!(stated::MAX_UNITS, crate::agent_door::MAX_UNITS);
    assert_eq!(
        stated::DIALECT_DOCUMENT,
        crate::door_statement::DIALECT_DOCUMENT
    );
    assert_eq!(
        stated::CLASS_BYTES_INDEX,
        crate::door_statement::CLASS_BYTES_INDEX
    );
    assert_eq!(
        stated::CLASS_FEE_INDEX,
        crate::door_statement::CLASS_FEE_INDEX
    );
    assert_eq!(stated::WELL_KNOWN_CARD_PATH, crate::WELL_KNOWN_CARD_PATH);
    assert_eq!(stated::HELD_KINDS, crate::records::HELD_KINDS);
    let routes: Vec<(&str, &str)> = crate::door_statement::ROUTES
        .iter()
        .map(|r| (r.verb, r.target))
        .collect();
    assert_eq!(stated::ROUTES, &routes[..]);
}
