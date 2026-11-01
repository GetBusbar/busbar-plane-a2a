// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::tests::raw_custody_probe::{assert_wiped, Probe, SECRET};

#[test]
fn cancelling_a_partial_far_answer_retires_its_initialized_body() {
    assert_wiped(|| {
        let mut relay = sent();
        assert_eq!(
            relay.on_piece(far(Some(STATUS_OK), SECRET, false)),
            PieceAnswer::Nothing
        );
        drop(relay);
    });
}

#[test]
fn retry_retires_the_old_far_answer_before_the_next_attempt() {
    let mut relay = sent();
    assert_eq!(
        relay.on_piece(far(Some(STATUS_OK), SECRET, false)),
        PieceAnswer::Nothing
    );
    let probe = Probe::start();
    assert!(matches!(
        relay.on_piece(kernel(Some(URL))),
        PieceAnswer::Attempt(_)
    ));
    probe.checkpoint();
}

#[test]
fn an_upstream_refusal_retires_the_private_body_without_echoing_it() {
    assert_wiped(|| {
        let mut relay = sent();
        let reply = answered(&mut relay, STATUS_BAD_GATEWAY, SECRET);
        assert!(!reply
            .body
            .windows(SECRET.len())
            .any(|bytes| bytes == SECRET));
        drop(relay);
    });
}
