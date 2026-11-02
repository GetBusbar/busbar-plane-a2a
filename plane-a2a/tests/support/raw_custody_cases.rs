// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Actual host callbacks preserve the retained body across a byte window, metadata SHORT,

use super::*;

const UNIT: u64 = 0x726177;
const SECRET: &str = "raw-a2a-custody-canary";
const REQUEST: &[u8] = br#"{"jsonrpc":"2.0","id":7,"method":"GetExtendedAgentCard","params":{"credentials":"raw-a2a-custody-canary"}}"#;
const REPLY: &[u8] =
    br#"{"jsonrpc":"2.0","id":7,"result":{"credentials":"raw-a2a-custody-canary"}}"#;
const HTTP_OK: u32 = 200;
const HTTP_UNAVAILABLE: u32 = 503;

fn ready(door: &Door) {
    let (outcome, status, body) = door.connect("vendor");
    assert_eq!((outcome, status), (Outcome::Ready, HTTP_OK), "{body}");
    assert_eq!(
        door.arrive(
            UNIT,
            ("POST", "/a2a/agents/{agent_id}"),
            "/a2a/agents/vendor",
            REQUEST
        ),
        (Outcome::Ready, 0)
    );
    let attempt = door.piece(UNIT, Given::attempt(b"vendor"), REQUEST.len());
    assert_eq!(attempt.outcome, Some(Outcome::Ready), "{attempt:?}");
}

#[test]
fn a_real_body_window_retains_the_exact_suffix_and_cancel_releases_the_unit() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let door = open();
    ready(&door);
    let prefix = REQUEST.len() / 2;
    let first = door.piece(UNIT, Given::caller(REQUEST), prefix);
    assert_eq!(first.outcome, Some(Outcome::Ready), "{first:?}");
    assert_eq!(first.emitted, REQUEST[..prefix]);
    assert_ne!(first.more, 0);
    let tail = door.piece(UNIT, Given::more(), REQUEST.len());
    assert_eq!(tail.outcome, Some(Outcome::Ready), "{tail:?}");
    assert_eq!(tail.emitted, REQUEST[prefix..]);
    assert_eq!(tail.more, 0);
    assert_eq!(door.cancel(UNIT), Outcome::Ready);
    assert!(!door.still_answers(UNIT));
}

#[test]
fn an_actual_metadata_short_preserves_the_reply_until_recall_or_cancel() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    for recall in [false, true] {
        let door = open();
        ready(&door);
        let sent = door.piece(UNIT, Given::caller(REQUEST), REQUEST.len());
        assert_eq!(sent.emitted, REQUEST);
        let short = door.piece_with_fields(UNIT, Given::far_end(HTTP_OK, REPLY), REPLY.len(), 0);
        assert_eq!(short.outcome, Some(Outcome::Failed), "{short:?}");
        assert!(short.fields_needed > 0);
        assert!(short.emitted.is_empty());
        if recall {
            let recalled = door.piece(UNIT, Given::more(), REPLY.len());
            assert_eq!(recalled.outcome, Some(Outcome::Ready), "{recalled:?}");
            assert_eq!(recalled.emitted, REPLY);
            assert_ne!(recalled.flags & EMIT_DONE, 0);
        }
        assert_eq!(door.cancel(UNIT), Outcome::Ready);
        assert!(!door.still_answers(UNIT));
    }
}

#[test]
fn a_real_upstream_error_does_not_echo_the_private_body_and_cancel_ends_its_owner() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let door = open();
    ready(&door);
    let sent = door.piece(UNIT, Given::caller(REQUEST), REQUEST.len());
    assert_eq!(sent.emitted, REQUEST);
    let answer = door.piece(
        UNIT,
        Given::far_end(HTTP_UNAVAILABLE, SECRET.as_bytes()),
        REQUEST.len(),
    );
    assert_eq!(answer.outcome, Some(Outcome::Ready), "{answer:?}");
    assert!(!String::from_utf8_lossy(&answer.emitted).contains(SECRET));
    assert_eq!(door.cancel(UNIT), Outcome::Ready);
    assert!(!door.still_answers(UNIT));
}
