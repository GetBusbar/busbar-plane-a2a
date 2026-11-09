// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Bounded signed-card reuse, invalidated by generation, source document and current signer id.

use std::sync::Arc;

use busbar_contract::abi::sdk::Keyed;
use serde_json::Value;

use crate::relay::RawBytes;
use crate::served_card::{sign_card, Signer};

type CacheKey = (u64, Option<String>);
const MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_ENTRIES: usize = 128;

struct Cached {
    source: Option<Arc<Value>>,
    kid: Option<String>,
    body: Arc<RawBytes>,
    modified: Option<u64>,
}

#[derive(Default)]
pub(crate) struct CardCache {
    entries: Keyed<CacheKey, Cached>,
}

impl CardCache {
    /// Validators describe the actual signed representation. Its modification
    /// time stays stable while those bytes remain cached, including short-write
    /// re-entry, and is learned only from a successful host-clock reading.
    pub(crate) fn validators(
        &self,
        generation: u64,
        body: &[u8],
        now: Option<u64>,
    ) -> (String, Option<String>) {
        use busbar_contract::abi::sdk::digest::{lower_hex, sha256};
        let etag = format!("\"{}\"", lower_hex(&sha256(body)));
        let modified = self.entries.with(&(generation, None), |cached| {
            let cached = cached.filter(|cached| cached.body.as_slice() == body)?;
            if cached.modified.is_none() {
                cached.modified = now;
            }
            cached.modified
        });
        (etag, modified.map(http_date))
    }

    pub(crate) fn retire(&self, generation: u64) {
        self.entries
            .with_all(|entries| entries.retain(|(held, _), _| *held != generation));
    }

    pub(crate) fn serve(
        &self,
        generation: u64,
        allow_cached: bool,
        agent: Option<&str>,
        source: Option<&Arc<Value>>,
        signer: &mut dyn Signer,
        build: impl FnOnce() -> Result<Value, String>,
    ) -> Result<Vec<u8>, String> {
        let key = (generation, agent.map(str::to_owned));
        let kid = signer.kid();
        if let Some(body) = self.entries.with(&key, |cached| {
            cached
                .filter(|cached| {
                    allow_cached
                        && cached.kid == kid
                        && match (&cached.source, source) {
                            (None, None) => true,
                            (Some(previous), Some(current)) => Arc::ptr_eq(previous, current),
                            _ => false,
                        }
                })
                .map(|cached| cached.body.clone())
        }) {
            return Ok(body.as_slice().to_vec());
        }
        let card = build()?;
        let signed = sign_card(
            &card,
            &mut KnownKey {
                signer,
                kid: kid.clone(),
            },
        )?;
        let body =
            crate::relay::json_bytes(&signed).map_err(|_| "card encoding failed".to_string())?;
        if body.len() <= MAX_BYTES {
            let modified = self.entries.with(&key, |previous| {
                previous
                    .filter(|previous| previous.body.as_slice() == body)
                    .and_then(|previous| previous.modified)
            });
            let cached = Cached {
                source: source.cloned(),
                kid,
                body: Arc::new(RawBytes::from(body.clone())),
                modified,
            };
            self.entries.with_all(|entries| {
                entries.remove(&key);
                let mut bytes: usize = entries.values().map(|entry| entry.body.len()).sum();
                while entries.len() >= MAX_ENTRIES
                    || bytes.saturating_add(cached.body.len()) > MAX_BYTES
                {
                    let Some((_, old)) = entries.pop_first() else {
                        break;
                    };
                    bytes = bytes.saturating_sub(old.body.len());
                }
                entries.insert(key, cached);
            });
        }
        Ok(body)
    }
}

fn http_date(seconds: u64) -> String {
    let days = seconds / 86_400;
    let time = seconds % 86_400;
    let (year, month, day) = busbar_contract::civil::civil_from_days(days as i64);
    let weekday = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"][(days % 7) as usize];
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ][(month - 1) as usize];
    format!(
        "{weekday}, {day:02} {month} {year:04} {:02}:{:02}:{:02} GMT",
        time / 3600,
        time / 60 % 60,
        time % 60
    )
}

struct KnownKey<'a> {
    signer: &'a mut dyn Signer,
    kid: Option<String>,
}

impl Signer for KnownKey<'_> {
    fn kid(&mut self) -> Option<String> {
        self.kid.clone()
    }
    fn sign(&mut self, input: &[u8]) -> Option<Vec<u8>> {
        self.signer.sign(input)
    }
}

#[cfg(test)]
#[path = "tests/served_card_cache_tests.rs"]
mod tests;
