// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The agent cards the plane holds, in plugin-owned memory: the

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_contract::abi::sdk::publish::Keyed;
use serde_json::Value;

/// The most cards held at once; past it, the smallest agent ids are dropped first.
pub const MAX_CARDS: usize = 4096;

/// The held cards, by agent and live generation. Only retirement removes a generation's card;
/// a slow admitted unit may outlive any number of later refreshes.
#[derive(Debug, Default)]
pub struct Cards {
    by_agent: Keyed<String, BTreeMap<u64, Arc<Value>>>,
}

impl Cards {
    /// Hold `card` for `agent` under `generation`, replacing only that generation's earlier card.
    pub fn hold(&self, agent: &str, generation: u64, card: Value) {
        self.hold_shared(agent, generation, Arc::new(card));
    }

    /// Keep the same card under another live generation without copying its document.
    pub fn hold_shared(&self, agent: &str, generation: u64, card: Arc<Value>) {
        self.by_agent.with_all(|m| {
            while m.len() >= MAX_CARDS && !m.contains_key(agent) {
                if m.pop_first().is_none() {
                    break;
                }
            }
            m.entry(agent.to_string())
                .or_default()
                .insert(generation, card);
        });
    }

    /// A restart's warm only fills a gap: a card held since the listing began wins.
    pub fn hold_if_none(&self, agent: &str, generation: u64, card: Value) -> bool {
        self.by_agent.with_all(|m| {
            if m.contains_key(agent) {
                return false;
            }
            while m.len() >= MAX_CARDS {
                if m.pop_first().is_none() {
                    break;
                }
            }
            m.insert(
                agent.to_string(),
                BTreeMap::from([(generation, Arc::new(card))]),
            );
            true
        })
    }

    /// Extend a completed warm to an unchanged registration without replacing a newer look.
    pub fn hold_shared_if_absent(&self, agent: &str, generation: u64, card: Arc<Value>) {
        self.by_agent.with(&agent.to_string(), |held| {
            if let Some(held) = held {
                held.entry(generation).or_insert(card);
            }
        });
    }

    /// The card held for `agent` under `generation`; `None` when none is, or it was held under

    #[must_use]
    pub fn at(&self, agent: &str, generation: u64) -> Option<Arc<Value>> {
        self.by_agent.with(&agent.to_string(), |held| {
            held.and_then(|cards| cards.get(&generation).cloned())
        })
    }

    /// Drop every card held under `generation` (its retire).
    pub fn retire(&self, generation: u64) {
        self.by_agent.with_all(|m| {
            m.retain(|_, cards| {
                cards.remove(&generation);
                !cards.is_empty()
            });
        });
    }
}

#[cfg(test)]
#[path = "tests/cards_tests.rs"]
mod tests;
