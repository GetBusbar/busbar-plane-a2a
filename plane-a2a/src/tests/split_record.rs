// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

const KIND: &str = "card";

/// A value `len` bytes long, no two neighbouring records alike.
fn value(len: usize) -> Vec<u8> {
    (0..len).map(|n| b'a' + (n % 26) as u8).collect()
}

/// The rows a store holds after `writes`, as `records.list` answers them (a tombstone drops one).
fn stored(writes: &[Write]) -> Vec<(String, Vec<u8>)> {
    let mut rows = std::collections::BTreeMap::new();
    for w in writes {
        if w.value.is_empty() {
            rows.remove(&w.key);
        } else {
            rows.insert(w.key.clone(), w.value.clone());
        }
    }
    rows.into_iter().collect()
}

#[test]
fn a_value_that_fits_is_one_record_under_its_key() {
    let v = value(MAX_RECORD_BYTES);
    let writes = split(KIND, "vendor", &v);
    assert_eq!(writes.len(), 1);
    assert_eq!((writes[0].key.as_str(), &writes[0].value), ("vendor", &v));
    let joined = join(stored(&writes));
    assert_eq!(joined.whole, vec![("vendor".to_string(), v)]);
    assert!(joined.refused.is_empty() && joined.stray.is_empty());
}

#[test]
fn a_longer_value_is_parts_at_most_the_ceiling_then_its_head_and_reads_back_whole() {
    let v = value(3 * MAX_RECORD_BYTES + 7);
    let writes = split(KIND, "vendor", &v);
    assert_eq!(writes.len(), 5, "four parts and the head");
    assert!(writes.iter().all(|w| w.value.len() <= MAX_RECORD_BYTES));
    assert!(writes.iter().all(|w| w.kind == KIND));
    let (head, parts) = writes.split_last().expect("a head");
    assert_eq!(head.key, "vendor", "the head goes last, under the key");
    assert!(head.value.starts_with(HEAD_TAG.as_bytes()));
    assert!(parts
        .iter()
        .all(|p| is_part(&p.key) && owner(&p.key) == "vendor"));
    let joined = join(stored(&writes));
    assert_eq!(joined.whole, vec![("vendor".to_string(), v)]);
    assert!(joined.refused.is_empty() && joined.stray.is_empty());
}

#[test]
fn a_head_whose_parts_are_partial_is_refused_and_its_parts_are_stray() {
    let v = value(2 * MAX_RECORD_BYTES + 1);
    let mut writes = split(KIND, "vendor", &v);
    writes.remove(1);
    let joined = join(stored(&writes));
    assert!(joined.whole.is_empty(), "a partial set is never read whole");
    assert_eq!(
        joined.refused,
        vec![("vendor".to_string(), "a part is missing")]
    );
    assert_eq!(joined.stray.len(), 2, "the parts it did write are stray");
}

#[test]
fn a_head_whose_parts_do_not_verify_is_refused() {
    let v = value(2 * MAX_RECORD_BYTES + 1);
    let mut writes = split(KIND, "vendor", &v);
    writes[0].value[0] ^= 1;
    let joined = join(stored(&writes));
    assert!(joined.whole.is_empty());
    assert_eq!(
        joined.refused,
        vec![(
            "vendor".to_string(),
            "its parts do not verify against its digest"
        )]
    );
    assert_eq!(joined.stray.len(), 3);
}

#[test]
fn parts_written_with_no_head_are_stray_and_never_read() {
    let v = value(2 * MAX_RECORD_BYTES);
    let mut writes = split(KIND, "vendor", &v);
    writes.pop();
    let joined = join(stored(&writes));
    assert!(joined.whole.is_empty() && joined.refused.is_empty());
    assert_eq!(joined.stray.len(), 2);
}

#[test]
fn a_new_value_never_writes_over_the_parts_its_older_head_names() {
    let (old, new) = (value(2 * MAX_RECORD_BYTES), value(2 * MAX_RECORD_BYTES + 3));
    let older = split(KIND, "vendor", &old);
    let newer = split(KIND, "vendor", &new);
    let keys = |w: &[Write]| -> Vec<String> {
        w.iter()
            .filter(|w| is_part(&w.key))
            .map(|w| w.key.clone())
            .collect()
    };
    assert!(keys(&older).iter().all(|k| !keys(&newer).contains(k)));
    // The new set's parts land and its head does not: the older head still reads whole.
    let mut torn = older.clone();
    torn.extend(newer.iter().filter(|w| is_part(&w.key)).cloned());
    let joined = join(stored(&torn));
    assert_eq!(joined.whole, vec![("vendor".to_string(), old)]);
    assert_eq!(joined.stray, keys(&newer));
}

#[test]
fn an_unreadable_head_is_refused() {
    for head in [
        "split/1 ",
        "split/1 2 1025",
        "split/1 x 1025 00",
        "split/1 3 1025 00",
        "split/1 1 10 0000000000000000000000000000000000000000000000000000000000000000",
    ] {
        let joined = join(vec![("vendor".to_string(), head.as_bytes().to_vec())]);
        assert_eq!(
            joined.refused,
            vec![("vendor".to_string(), "an unreadable head")],
            "{head}"
        );
    }
}
