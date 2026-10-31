// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The agent cards the plane holds, in plugin-owned memory: the
//! mirror of the `card` host records ([`crate::records::KIND_CARD`], keyed by agent id, operator
//! scope). The `connect` and `approve` answers write a card their look verified (record
//! writes ride an answer, never a tick), and the first tick after `open` warms this
//! mirror from those records (`records.list`), so an instance opened again holds the cards its
//! operator approved before. A held card is valid to the
//! refresh generation it was held under: `arrive` does no I/O and reads only this memory, and a
//! card held under another generation is not read. SEVERAL GENERATIONS ARE LIVE AT ONCE (a unit
//! keeps the generation it arrived under until it ends, and the kernel retires a generation
//! later), so each agent's card is held per generation: a hold under one generation leaves every
//! other generation's card as it was, and a retire drops only its own.

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_contract::abi::sdk::publish::Keyed;
use serde_json::Value;

/// The most cards held at once; past it, the smallest agent ids are dropped first.
pub const MAX_CARDS: usize = 4096;

/// The most generations one agent's card is held under at once; past it, the oldest generation's
/// is dropped first (a hold that lands under a generation already retired never grows the map
/// past it).
pub const MAX_GENERATIONS_PER_CARD: usize = 4;

/// The held cards, by agent id, each under the generations it was held under.
#[derive(Debug, Default)]
pub struct Cards {
    by_agent: Keyed<String, BTreeMap<u64, Arc<Value>>>,
}

impl Cards {
    /// Hold `card` for `agent` under `generation`, in place of any earlier one under it.
    pub fn hold(&self, agent: &str, generation: u64, card: Value) {
        self.hold_shared(agent, generation, Arc::new(card));
    }

    /// [`Cards::hold`] of a card already shared (held under another generation too).
    pub fn hold_shared(&self, agent: &str, generation: u64, card: Arc<Value>) {
        self.by_agent.with_all(|m| {
            while m.len() >= MAX_CARDS && !m.contains_key(agent) {
                if m.pop_first().is_none() {
                    break;
                }
            }
            let held = m.entry(agent.to_string()).or_default();
            held.insert(generation, card);
            while held.len() > MAX_GENERATIONS_PER_CARD {
                held.pop_first();
            }
        });
    }

    /// The card held for `agent` under `generation`; `None` when none is held under it.
    #[must_use]
    pub fn at(&self, agent: &str, generation: u64) -> Option<Arc<Value>> {
        self.by_agent.with(&agent.to_string(), |held| {
            held.and_then(|h| h.get(&generation).cloned())
        })
    }

    /// Drop every card held under `generation` (its retire).
    pub fn retire(&self, generation: u64) {
        self.by_agent.with_all(|m| {
            m.retain(|_, held| {
                held.remove(&generation);
                !held.is_empty()
            });
        });
    }
}

#[cfg(test)]
#[path = "tests/cards_tests.rs"]
mod tests;
