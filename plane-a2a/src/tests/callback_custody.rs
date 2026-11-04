// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Keep the input document alive outside the probe so only the typed copy can satisfy it.

use crate::a2a::task::{Direction, Task};
use crate::local::PushConfig;
use crate::tests::request_custody_probe::assert_wiped;
use serde::Deserialize;

const SECRET: &str = "callback-credential-custody-canary";

fn task() -> Task {
    Task::submitted("t", "c", "p", Direction::Inbound, 1).unwrap()
}

#[test]
fn incomplete_record_visitors_wipe_their_typed_callback_copy() {
    let row = task().to_row();
    let mut document = serde_json::to_value(&row).unwrap();
    document["push_callback"] = SECRET.into();
    // Lexical map order decodes push_callback before this malformed later field.
    document["updated_at"] = "invalid".into();
    assert_wiped(|| assert!(crate::TaskRow::deserialize(&document).is_err()));
    assert_eq!(document["push_callback"], SECRET);

    let document = serde_json::json!({"id":"c", "url":SECRET, "version":[]});
    assert_wiped(|| assert!(PushConfig::deserialize(&document).is_err()));
    assert_eq!(document["url"], SECRET);
}

#[test]
fn complete_callback_owners_and_each_canonical_clone_wipe_and_redact() {
    let document = serde_json::json!({"id":"c", "url":SECRET});
    let config = PushConfig::deserialize(&document).unwrap();
    assert!(!format!("{config:?}").contains(SECRET));
    assert_wiped(|| drop(config));

    let mut canonical = task();
    canonical.push_callback = Some(SECRET.into());
    let cloned = canonical.clone();
    let row = canonical.to_row();
    let delivery = crate::push::Delivery::of(&canonical).unwrap();
    assert!(!format!("{canonical:?} {delivery:?}").contains(SECRET));
    assert_wiped(|| drop(canonical));
    assert_wiped(|| drop(cloned));
    assert_wiped(|| drop(row));
    assert_wiped(|| drop(delivery));
}

#[test]
fn capture_wipes_the_superseded_legacy_callback_before_transfer() {
    let mut canonical = task();
    canonical.push_callback = Some(SECRET.into());
    let row = canonical.to_row();
    let config = PushConfig {
        id: "c".into(),
        url: "https://new.example/callback".into(),
        authentication: None,
        version: "1.0".into(),
    };
    // Neither borrowed source retires in this scope; only the superseded Task copy matches.
    assert_wiped(|| {
        let delivery = crate::push_door::captured(&row, Some(&config)).unwrap();
        assert_eq!(delivery.url, config.url);
    });
    assert_eq!(row.push_callback, SECRET);
}

#[test]
fn invalid_canonical_identity_retires_the_callback_copy() {
    let mut canonical = task();
    canonical.push_callback = Some(SECRET.into());
    let mut row = canonical.to_row();
    row.principal.clear();
    assert_wiped(|| assert!(Task::from_row(&row).is_err()));
    assert_eq!(row.push_callback, SECRET);
}
