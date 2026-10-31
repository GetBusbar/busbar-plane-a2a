// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The held cards: read only under the generation they were held under.

use serde_json::json;

use super::*;

#[test]
fn a_card_held_under_a_generation_is_read_under_it_only() {
    let cards = Cards::default();
    assert_eq!(cards.at("planner", 1), None);
    cards.hold("planner", 1, json!({ "name": "P" }));
    assert_eq!(
        cards.at("planner", 1).as_deref(),
        Some(&json!({ "name": "P" }))
    );
    assert_eq!(
        cards.at("planner", 2),
        None,
        "a stale generation is not read"
    );
    assert_eq!(cards.at("other", 1), None);
}

#[test]
fn a_newer_hold_replaces_the_card_and_retire_drops_its_generation() {
    let cards = Cards::default();
    cards.hold("planner", 1, json!({ "v": 1 }));
    cards.hold("planner", 2, json!({ "v": 2 }));
    assert_eq!(cards.at("planner", 1), None);
    assert_eq!(cards.at("planner", 2).as_deref(), Some(&json!({ "v": 2 })));
    cards.retire(1);
    assert!(cards.at("planner", 2).is_some());
    cards.retire(2);
    assert_eq!(cards.at("planner", 2), None);
}

/// G1-1: SEVERAL GENERATIONS ARE LIVE AT ONCE, and each keeps the card held under it: a hold under
/// the next generation leaves the one before readable (its units still run on it), a late hold
/// under the older generation leaves the newer one's card as it was, and a retire drops only its
/// own generation.
#[test]
fn every_live_generation_keeps_its_own_card() {
    let cards = Cards::default();
    cards.hold("planner", 1, json!({ "v": 1 }));
    cards.hold("planner", 2, json!({ "v": 1 }));
    assert_eq!(cards.at("planner", 1).as_deref(), Some(&json!({ "v": 1 })));
    assert_eq!(cards.at("planner", 2).as_deref(), Some(&json!({ "v": 1 })));
    // A look that pended across the refresh lands under the unit's older generation.
    cards.hold("planner", 1, json!({ "v": 2 }));
    assert_eq!(cards.at("planner", 1).as_deref(), Some(&json!({ "v": 2 })));
    assert_eq!(cards.at("planner", 2).as_deref(), Some(&json!({ "v": 1 })));
    cards.retire(1);
    assert_eq!(cards.at("planner", 1), None);
    assert_eq!(cards.at("planner", 2).as_deref(), Some(&json!({ "v": 1 })));
}
