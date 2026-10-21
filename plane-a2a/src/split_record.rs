// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A VALUE OF ANY SIZE AS HOST RECORDS OF AT MOST [`MAX_RECORD_BYTES`] EACH.
//!
//! A host record is at most [`MAX_RECORD_BYTES`] by design (`busbar_contract::kinds::RecordBytes`:
//! a journal of fixed-size records replays by arithmetic), and an agent's card or the skills its
//! operator approved are routinely longer. What must survive a restart goes to its records
//! (`BUSBAR-1.6.0.md` l.345-346), so a value past the ceiling is kept as several records of its
//! kind:
//!
//! * a value that fits is ONE record under its key, as it always was;
//! * a longer one is its PARTS, each at most the ceiling, under the derived keys
//!   `<key>/<digest>/<n>` (`<digest>` the first [`PART_DIGEST_HEX`] hex digits of the whole
//!   value's SHA-256, so a new value never writes over the parts an older head names), then its
//!   HEAD under `<key>`: [`HEAD_TAG`], the part count, the whole length and the whole SHA-256 in
//!   hex. The parts go first and the head last, so a head is only ever read over parts that were
//!   written before it;
//! * a read ([`rejoin`]) reassembles each head's parts and checks the length and the digest: a set
//!   that is partial or does not verify is refused (never read as whole), and a part no whole value
//!   names is stray. A later write of the key tombstones the parts it no longer names.
//!
//! A key the plane keeps this way never holds a `/` (an agent id is one path segment), so a key
//! with one is a part.

use busbar_contract::abi::sdk::digest::{lower_hex, sha256};
use busbar_contract::bounded::MAX_RECORD_BYTES;

use crate::tasks::Write;

/// What a head record's value starts with: a split value's head, never a value the plane writes
/// whole (those are JSON objects).
pub const HEAD_TAG: &str = "split/1 ";

/// How many hex digits of the whole value's digest a part key carries.
pub const PART_DIGEST_HEX: usize = 16;

/// Whether `key` names a part of a split value rather than a value or a head.
#[must_use]
pub fn is_part(key: &str) -> bool {
    key.contains('/')
}

/// The key a part key is a part of.
#[must_use]
pub fn owner(part: &str) -> &str {
    part.split_once('/').map_or(part, |(key, _)| key)
}

/// The key of part `n` of the value whose digest is `hex`, under `key`.
fn part_key(key: &str, hex: &str, n: usize) -> String {
    format!("{key}/{}/{n}", &hex[..PART_DIGEST_HEX.min(hex.len())])
}

/// The records that keep `value` under `key` of `kind`, in the order they are to be written: the
/// one record when it fits the ceiling; otherwise every part, then the head.
#[must_use]
pub fn split_value(kind: &'static str, key: &str, value: &[u8]) -> Vec<Write> {
    if value.len() <= MAX_RECORD_BYTES {
        return vec![Write {
            kind,
            key: key.to_string(),
            value: value.to_vec(),
        }];
    }
    let hex = lower_hex(&sha256(value));
    let parts = value.chunks(MAX_RECORD_BYTES);
    let count = parts.len();
    let mut writes: Vec<Write> = parts
        .enumerate()
        .map(|(n, part)| Write {
            kind,
            key: part_key(key, &hex, n),
            value: part.to_vec(),
        })
        .collect();
    writes.push(Write {
        kind,
        key: key.to_string(),
        value: format!("{HEAD_TAG}{count} {} {hex}", value.len()).into_bytes(),
    });
    writes
}

/// What a [`rejoin`] of one kind's records read.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Joined {
    /// Every value read whole, by its key.
    pub whole: Vec<(String, Vec<u8>)>,
    /// Every head whose parts are missing or do not verify, by its key, and why: never read.
    pub refused: Vec<(String, &'static str)>,
    /// Every part key no whole value names.
    pub stray: Vec<String>,
}

/// One kind's `rows` (`(key, value)`, as `records.list` answers them) read back: each value
/// written whole, and each split value reassembled from its parts and verified.
#[must_use]
pub fn rejoin(rows: Vec<(String, Vec<u8>)>) -> Joined {
    let (parts, heads): (Vec<_>, Vec<_>) = rows.into_iter().partition(|(key, _)| is_part(key));
    let mut parts: std::collections::BTreeMap<String, Vec<u8>> = parts.into_iter().collect();
    let mut joined = Joined::default();
    for (key, value) in heads {
        let Some(head) = value.strip_prefix(HEAD_TAG.as_bytes()) else {
            joined.whole.push((key, value));
            continue;
        };
        match assemble(&key, head, &mut parts) {
            Ok(whole) => joined.whole.push((key, whole)),
            Err(why) => joined.refused.push((key, why)),
        }
    }
    joined.stray = parts.into_keys().collect();
    joined
}

/// The value the head `head` (past its tag) of `key` names, its parts taken out of `parts` once it
/// verifies; why not when the head is unreadable, a part is missing, or the whole does not verify
/// (its parts are then left in `parts`, stray).
fn assemble(
    key: &str,
    head: &[u8],
    parts: &mut std::collections::BTreeMap<String, Vec<u8>>,
) -> Result<Vec<u8>, &'static str> {
    const UNREADABLE: &str = "an unreadable head";
    let head = std::str::from_utf8(head).map_err(|_| UNREADABLE)?;
    let mut fields = head.split(' ');
    let (Some(count), Some(len), Some(hex), None) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return Err(UNREADABLE);
    };
    let (Ok(count), Ok(len)) = (count.parse::<usize>(), len.parse::<usize>()) else {
        return Err(UNREADABLE);
    };
    let digest = hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if !digest || len <= MAX_RECORD_BYTES || count != len.div_ceil(MAX_RECORD_BYTES) {
        return Err(UNREADABLE);
    }
    // A STORED HEAD NAMES NO MORE PARTS THAN WERE READ: its count is bounded by the rows the read
    // answered before any key list is built or any byte is joined, so a corrupt head cannot size
    // an allocation of its own choosing.
    if count > parts.len() {
        return Err("a part is missing");
    }
    let keys: Vec<String> = (0..count).map(|n| part_key(key, hex, n)).collect();
    let mut whole = Vec::with_capacity(len.min(count.saturating_mul(MAX_RECORD_BYTES)));
    for k in &keys {
        whole.extend_from_slice(parts.get(k).ok_or("a part is missing")?);
    }
    if whole.len() != len || lower_hex(&sha256(&whole)) != hex {
        return Err("its parts do not verify against its digest");
    }
    for k in &keys {
        parts.remove(k);
    }
    Ok(whole)
}

#[cfg(test)]
#[path = "tests/split_record.rs"]
mod tests;
