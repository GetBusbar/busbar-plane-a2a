// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::tests::raw_custody_probe::{assert_wiped, Probe, SECRET};

#[test]
fn growth_retires_the_initialized_old_allocation_before_the_new_owner_ends() {
    let mut bytes = RawBytes::from(SECRET.to_vec());
    let probe = Probe::start();
    let extension = vec![b'x'; bytes.0.capacity() + SECRET.len()];
    bytes.extend_from_slice(&extension);
    probe.checkpoint();
    assert!(bytes.starts_with(SECRET));
    assert!(bytes.ends_with(&extension));
    drop(bytes);
    probe.checkpoint();
}

#[test]
fn retry_clear_and_independent_clone_each_wipe_their_own_initialized_prefix() {
    assert_wiped(|| {
        let mut bytes = RawBytes::from(SECRET.to_vec());
        let cloned = bytes.clone();
        bytes.clear();
        assert!(bytes.is_empty());
        assert_eq!(&*cloned, SECRET);
        drop(cloned);
    });
}

#[test]
fn removing_a_grpc_prefix_wipes_the_vacated_initialized_tail() {
    let mut bytes = RawBytes::from([SECRET, SECRET].concat());
    let probe = Probe::start();
    bytes.discard_prefix(SECRET.len());
    probe.checkpoint();
    assert_eq!(&*bytes, SECRET);
    drop(bytes);
    probe.checkpoint();
}

#[test]
fn cancelling_a_relay_releases_its_pending_grpc_bytes() {
    assert_wiped(|| {
        let mut relay = HopRelay::new(Value::Null, crate::framed::DEFAULT_VERSION);
        relay.grpc.pending.extend_from_slice(SECRET);
        drop(relay);
    });
}

#[test]
fn reading_an_out_of_range_number_borrows_the_exact_original_without_a_raw_copy() {
    let body = br#"{"jsonrpc":"2.0","id":7,"result":{"credential":"raw-a2a-custody-canary","large":1e400}}"#;
    let probe = Probe::start();
    {
        let reading = crate::answer_bytes::readable(body);
        assert!(matches!(reading, std::borrow::Cow::Borrowed(_)));
        assert_eq!(reading.as_ptr(), body.as_ptr());
        let span = read_answer(STATUS_OK, body, &serde_json::json!(7)).unwrap();
        assert_eq!(
            &body[span],
            br#"{"credential":"raw-a2a-custody-canary","large":1e400}"#
        );
    }
    assert_eq!(
        probe.retirements(),
        0,
        "the reader creates no normalized raw owner"
    );
}
