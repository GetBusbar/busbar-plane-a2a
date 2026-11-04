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
fn a_newer_hold_preserves_live_cards_and_retire_drops_only_its_generation() {
    let cards = Cards::default();
    cards.hold("planner", 1, json!({ "v": 1 }));
    cards.hold("planner", 2, json!({ "v": 2 }));
    assert_eq!(cards.at("planner", 1).as_deref(), Some(&json!({ "v": 1 })));
    assert_eq!(cards.at("planner", 2).as_deref(), Some(&json!({ "v": 2 })));
    cards.retire(1);
    assert!(cards.at("planner", 2).is_some());
    cards.retire(2);
    assert_eq!(cards.at("planner", 2), None);
}

#[test]
fn more_than_four_live_generations_keep_their_cards_until_each_retires() {
    let cards = Cards::default();
    for generation in 1..=9 {
        cards.hold("planner", generation, json!({ "generation": generation }));
    }
    cards.hold("planner", 1, json!({ "generation": 1, "late": true }));
    assert_eq!(
        cards.at("planner", 1).unwrap()["late"],
        true,
        "a later hold replaces that generation's card"
    );
    assert!(cards.at("planner", 2).unwrap().get("late").is_none());
    for generation in 1..=9 {
        assert_eq!(
            cards.at("planner", generation).unwrap()["generation"],
            generation
        );
    }
    cards.retire(5);
    assert!(cards.at("planner", 5).is_none());
    for generation in [1, 2, 3, 4, 6, 7, 8, 9] {
        assert!(cards.at("planner", generation).is_some());
    }
}

/// RED before the fix: the warm's gap test was keyed on the agent alone, so a card a newer
/// generation held during the listing left the warmed generation with none.
#[test]
fn a_warm_fills_its_generation_even_when_another_generation_holds_a_card() {
    let cards = Cards::default();
    cards.hold("planner", 2, json!({ "look": "fresh" }));
    assert!(cards.hold_if_none("planner", 1, json!({ "look": "stored" })));
    assert_eq!(cards.at("planner", 1).unwrap()["look"], "stored");
    assert_eq!(
        cards.at("planner", 2).unwrap()["look"],
        "fresh",
        "the newer generation's card is untouched"
    );
    assert!(
        !cards.hold_if_none("planner", 2, json!({ "look": "stored" })),
        "a card held under the warmed generation wins"
    );
    assert_eq!(cards.at("planner", 2).unwrap()["look"], "fresh");
}

#[test]
fn fit_caches_parse_failures_and_replacement_invalidates_the_cache() {
    let cards = Cards::default();
    let shape = TaskShape::default();
    assert_eq!(cards.fit("p", 1, &shape), Err(Unfit::NoCachedCard));
    cards.hold("p", 1, json!(false));
    assert_eq!(
        cards.fit("p", 1, &shape),
        Err(Unfit::Unreadable(Unreadable::NotAnObject))
    );
    cards.by_agent.with(&"p".to_string(), |held| {
        assert!(held.unwrap().get(&1).unwrap().typed.get().is_some());
    });
    cards.hold("p", 1, json!({}));
    assert_eq!(cards.fit("p", 1, &shape), Ok(None));
}

#[test]
fn shared_document_generations_share_the_typed_cache() {
    let cards = Cards::default();
    let document = Arc::new(json!({}));
    cards.hold_shared("p", 1, Arc::clone(&document));
    let _ = cards.fit("p", 1, &TaskShape::default());
    cards.hold_shared("p", 2, Arc::clone(&document));
    cards.hold_shared_if_absent("p", 3, document);
    cards.by_agent.with(&"p".to_string(), |held| {
        let held = held.unwrap();
        assert!(Arc::ptr_eq(&held[&1], &held[&2]));
        assert!(Arc::ptr_eq(&held[&1], &held[&3]));
        assert!(held[&3].typed.get().is_some());
    });
}
